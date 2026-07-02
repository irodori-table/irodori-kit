use crate::resolved::{ResolvedProxyHopConfig, ResolvedSshAuth, ResolvedTransport};

// ---- Network Primitives and Protocols ----

pub type Result<T> = std::result::Result<T, ProxyError>;

#[derive(Debug, thiserror::Error)]
pub enum ProxyError {
    #[error("{context}: {source}")]
    Io {
        context: &'static str,
        #[source]
        source: std::io::Error,
    },
    #[error("{context}: {source}")]
    Ssh {
        context: &'static str,
        #[source]
        source: ssh2::Error,
    },
    #[error("{context}: {source}")]
    Context {
        context: String,
        #[source]
        source: Box<ProxyError>,
    },
    #[error("{0}")]
    Protocol(String),
}

impl ProxyError {
    pub(crate) fn io(context: &'static str, source: std::io::Error) -> Self {
        Self::Io { context, source }
    }

    fn ssh(context: &'static str, source: ssh2::Error) -> Self {
        Self::Ssh { context, source }
    }

    fn protocol(message: impl Into<String>) -> Self {
        Self::Protocol(message.into())
    }

    pub fn context(self, context: impl Into<String>) -> Self {
        Self::Context {
            context: context.into(),
            source: Box::new(self),
        }
    }
}

fn base64_encode(input: &[u8]) -> String {
    const CHARSET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut result = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        match chunk.len() {
            3 => {
                let b = ((chunk[0] as u32) << 16) | ((chunk[1] as u32) << 8) | (chunk[2] as u32);
                result.push(CHARSET[((b >> 18) & 0x3f) as usize] as char);
                result.push(CHARSET[((b >> 12) & 0x3f) as usize] as char);
                result.push(CHARSET[((b >> 6) & 0x3f) as usize] as char);
                result.push(CHARSET[(b & 0x3f) as usize] as char);
            }
            2 => {
                let b = ((chunk[0] as u32) << 10) | ((chunk[1] as u32) << 2);
                result.push(CHARSET[((b >> 12) & 0x3f) as usize] as char);
                result.push(CHARSET[((b >> 6) & 0x3f) as usize] as char);
                result.push(CHARSET[(b & 0x3f) as usize] as char);
                result.push('=');
            }
            1 => {
                let b = (chunk[0] as u32) << 4;
                result.push(CHARSET[((b >> 6) & 0x3f) as usize] as char);
                result.push(CHARSET[(b & 0x3f) as usize] as char);
                result.push('=');
                result.push('=');
            }
            _ => unreachable!(),
        }
    }
    result
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

pub fn socks5_handshake_sync<S>(
    mut stream: S,
    host: &str,
    port: u16,
    auth: Option<(&str, &str)>,
) -> Result<S>
where
    S: std::io::Read + std::io::Write,
{
    // 1. Greeting
    let mut greeting = vec![0x05];
    if auth.is_some() {
        greeting.push(2);
        greeting.push(0x00); // No authentication
        greeting.push(0x02); // Username/password
    } else {
        greeting.push(1);
        greeting.push(0x00);
    }
    stream
        .write_all(&greeting)
        .map_err(|e| ProxyError::io("socks5 greeting write failed", e))?;

    let mut resp = [0u8; 2];
    stream
        .read_exact(&mut resp)
        .map_err(|e| ProxyError::io("socks5 greeting read failed", e))?;
    if resp[0] != 0x05 {
        return Err(ProxyError::protocol(format!(
            "invalid socks5 version: {}",
            resp[0]
        )));
    }

    match resp[1] {
        0x00 => {}
        0x02 => {
            let (user, pass) =
                auth.ok_or_else(|| ProxyError::protocol("socks5 credentials missing"))?;
            if user.len() > 255 || pass.len() > 255 {
                return Err(ProxyError::protocol("socks5 username or password too long"));
            }
            let mut auth_req = vec![0x01, user.len() as u8];
            auth_req.extend_from_slice(user.as_bytes());
            auth_req.push(pass.len() as u8);
            auth_req.extend_from_slice(pass.as_bytes());
            stream
                .write_all(&auth_req)
                .map_err(|e| ProxyError::io("socks5 auth write failed", e))?;

            let mut auth_resp = [0u8; 2];
            stream
                .read_exact(&mut auth_resp)
                .map_err(|e| ProxyError::io("socks5 auth read failed", e))?;
            if auth_resp[0] != 0x01 {
                return Err(ProxyError::protocol(format!(
                    "invalid socks5 auth subversion: {}",
                    auth_resp[0]
                )));
            }
            if auth_resp[1] != 0x00 {
                return Err(ProxyError::protocol(format!(
                    "socks5 auth failed: status {}",
                    auth_resp[1]
                )));
            }
        }
        0xFF => return Err(ProxyError::protocol("socks5: no acceptable auth methods")),
        other => {
            return Err(ProxyError::protocol(format!(
                "socks5: unsupported auth method: {other}"
            )))
        }
    }

    // 2. CONNECT request
    let mut conn_req = vec![0x05, 0x01, 0x00];
    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        match ip {
            std::net::IpAddr::V4(ipv4) => {
                conn_req.push(0x01);
                conn_req.extend_from_slice(&ipv4.octets());
            }
            std::net::IpAddr::V6(ipv6) => {
                conn_req.push(0x04);
                conn_req.extend_from_slice(&ipv6.octets());
            }
        }
    } else {
        if host.len() > 255 {
            return Err(ProxyError::protocol("target host too long for socks5"));
        }
        conn_req.push(0x03);
        conn_req.push(host.len() as u8);
        conn_req.extend_from_slice(host.as_bytes());
    }
    conn_req.extend_from_slice(&port.to_be_bytes());
    stream
        .write_all(&conn_req)
        .map_err(|e| ProxyError::io("socks5 connect write failed", e))?;

    // 3. Response
    let mut conn_resp_header = [0u8; 4];
    stream
        .read_exact(&mut conn_resp_header)
        .map_err(|e| ProxyError::io("socks5 connect response read failed", e))?;
    if conn_resp_header[0] != 0x05 {
        return Err(ProxyError::protocol(format!(
            "invalid socks5 reply version: {}",
            conn_resp_header[0]
        )));
    }
    if conn_resp_header[1] != 0x00 {
        return Err(ProxyError::protocol(format!(
            "socks5 connect failed: status {}",
            conn_resp_header[1]
        )));
    }

    match conn_resp_header[3] {
        0x01 => {
            let mut buf = [0u8; 6];
            stream
                .read_exact(&mut buf)
                .map_err(|e| ProxyError::io("socks5 bind read failed", e))?;
        }
        0x04 => {
            let mut buf = [0u8; 18];
            stream
                .read_exact(&mut buf)
                .map_err(|e| ProxyError::io("socks5 bind read failed", e))?;
        }
        0x03 => {
            let mut len_buf = [0u8; 1];
            stream
                .read_exact(&mut len_buf)
                .map_err(|e| ProxyError::io("socks5 bind read failed", e))?;
            let domain_len = len_buf[0] as usize;
            let mut domain_buf = vec![0u8; domain_len + 2];
            stream
                .read_exact(&mut domain_buf)
                .map_err(|e| ProxyError::io("socks5 bind read failed", e))?;
        }
        other => {
            return Err(ProxyError::protocol(format!(
                "socks5: invalid reply address type: {other}"
            )))
        }
    }

    Ok(stream)
}

pub fn http_connect_handshake_sync<S>(
    mut stream: S,
    host: &str,
    port: u16,
    auth: Option<(&str, &str)>,
) -> Result<S>
where
    S: std::io::Read + std::io::Write,
{
    let mut req_str = format!(
        "CONNECT {host}:{port} HTTP/1.1\r\n\
         Host: {host}:{port}\r\n"
    );
    if let Some((user, pass)) = auth {
        let auth_str = format!("{user}:{pass}");
        let base64_auth = base64_encode(auth_str.as_bytes());
        req_str.push_str(&format!("Proxy-Authorization: Basic {base64_auth}\r\n"));
    }
    req_str.push_str("\r\n");

    stream
        .write_all(req_str.as_bytes())
        .map_err(|e| ProxyError::io("HTTP CONNECT write failed", e))?;

    let mut header_buf = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        stream
            .read_exact(&mut byte)
            .map_err(|e| ProxyError::io("HTTP CONNECT response read failed", e))?;
        header_buf.push(byte[0]);
        if header_buf.len() > 4096 {
            return Err(ProxyError::protocol(
                "HTTP CONNECT response header too large (> 4096 bytes)",
            ));
        }
        if header_buf.ends_with(b"\r\n\r\n") {
            break;
        }
    }

    let resp_str = String::from_utf8_lossy(&header_buf);
    let mut lines = resp_str.lines();
    let status_line = lines
        .next()
        .ok_or_else(|| ProxyError::protocol("empty HTTP CONNECT response"))?;

    let parts: Vec<&str> = status_line.split_whitespace().collect();
    if parts.len() < 2 {
        return Err(ProxyError::protocol(format!(
            "invalid HTTP status line: {status_line}"
        )));
    }
    let code = parts[1];
    if code != "200" {
        return Err(ProxyError::protocol(format!(
            "HTTP CONNECT failed: {status_line}"
        )));
    }

    Ok(stream)
}

pub enum HopStream {
    Tcp(std::net::TcpStream),
    Ssh(ssh2::Channel),
}

impl std::io::Read for HopStream {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            Self::Tcp(s) => s.read(buf),
            Self::Ssh(c) => c.read(buf),
        }
    }
}

impl std::io::Write for HopStream {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        match self {
            Self::Tcp(s) => s.write(buf),
            Self::Ssh(c) => c.write(buf),
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        match self {
            Self::Tcp(s) => s.flush(),
            Self::Ssh(c) => c.flush(),
        }
    }
}

fn establish_ssh_session(
    stream: std::net::TcpStream,
    username: &str,
    auth: &ResolvedSshAuth,
    strict_host_key: bool,
    expected_host_key: Option<&str>,
) -> Result<ssh2::Session> {
    let mut sess =
        ssh2::Session::new().map_err(|e| ProxyError::ssh("failed to create SSH session", e))?;
    sess.set_tcp_stream(stream);
    sess.handshake()
        .map_err(|e| ProxyError::ssh("SSH handshake failed", e))?;

    if strict_host_key {
        let (actual_key, _key_type) = sess
            .host_key()
            .ok_or_else(|| ProxyError::protocol("failed to get SSH host key"))?;
        if let Some(expected) = expected_host_key {
            let actual_hex = hex_encode(actual_key);
            let actual_b64 = base64_encode(actual_key);
            if expected != actual_hex && expected != actual_b64 {
                return Err(ProxyError::protocol(format!(
                    "Host key verification failed. Expected: {expected}, Got (hex): {actual_hex} or (b64): {actual_b64}"
                )));
            }
        } else {
            return Err(ProxyError::protocol(
                "strictHostKey is enabled but no hostKey was provided",
            ));
        }
    }

    match auth {
        ResolvedSshAuth::Agent => {
            let mut agent = sess
                .agent()
                .map_err(|e| ProxyError::ssh("failed to connect to SSH agent", e))?;
            agent
                .connect()
                .map_err(|e| ProxyError::ssh("failed to connect to SSH agent", e))?;
            agent
                .list_identities()
                .map_err(|e| ProxyError::ssh("failed to list SSH agent identities", e))?;
            let mut authenticated = false;
            for identity in agent
                .identities()
                .map_err(|e| ProxyError::ssh("failed to get SSH agent identities", e))?
            {
                if agent.userauth(username, &identity).is_ok() {
                    authenticated = true;
                    break;
                }
            }
            if !authenticated {
                return Err(ProxyError::protocol(
                    "SSH agent authentication failed: no identity accepted",
                ));
            }
        }
        ResolvedSshAuth::Password(password) => {
            sess.userauth_password(username, password)
                .map_err(|e| ProxyError::ssh("SSH password authentication failed", e))?;
        }
        ResolvedSshAuth::PrivateKey {
            private_key,
            passphrase,
        } => {
            sess.userauth_pubkey_memory(username, None, private_key, passphrase.as_deref())
                .map_err(|e| ProxyError::ssh("SSH private key authentication failed", e))?;
        }
    }

    if !sess.authenticated() {
        return Err(ProxyError::protocol("SSH session authentication failed"));
    }

    Ok(sess)
}

pub struct TunneledStream {
    pub stream: HopStream,
    pub session: Option<ssh2::Session>,
}

impl TunneledStream {
    pub fn set_nonblocking(&self, nonblocking: bool) -> Result<()> {
        match &self.stream {
            HopStream::Tcp(s) => s
                .set_nonblocking(nonblocking)
                .map_err(|e| ProxyError::io("failed to configure TCP stream blocking mode", e))?,
            HopStream::Ssh(_) => {
                if let Some(sess) = &self.session {
                    sess.set_blocking(!nonblocking);
                }
            }
        }
        Ok(())
    }
}

pub fn dial_resolved_transport(config: &ResolvedTransport) -> Result<TunneledStream> {
    match config {
        ResolvedTransport::Socks5Proxy(proxy) => {
            let stream = std::net::TcpStream::connect((proxy.host.as_str(), proxy.port))
                .map_err(|e| ProxyError::io("failed to connect to SOCKS5 proxy", e))?;
            let auth = proxy
                .auth
                .as_ref()
                .map(|a| (a.username.as_str(), a.password.as_str()));
            let stream =
                socks5_handshake_sync(stream, &proxy.target_host, proxy.target_port, auth)?;
            Ok(TunneledStream {
                stream: HopStream::Tcp(stream),
                session: None,
            })
        }
        ResolvedTransport::HttpConnectProxy(proxy) => {
            let stream = std::net::TcpStream::connect((proxy.host.as_str(), proxy.port))
                .map_err(|e| ProxyError::io("failed to connect to HTTP proxy", e))?;
            let auth = proxy
                .auth
                .as_ref()
                .map(|a| (a.username.as_str(), a.password.as_str()));
            let stream =
                http_connect_handshake_sync(stream, &proxy.target_host, proxy.target_port, auth)?;
            Ok(TunneledStream {
                stream: HopStream::Tcp(stream),
                session: None,
            })
        }
        ResolvedTransport::SshTunnel(tunnel) => {
            let stream = std::net::TcpStream::connect((tunnel.ssh_host.as_str(), tunnel.ssh_port))
                .map_err(|e| ProxyError::io("failed to connect to SSH host", e))?;
            let sess = establish_ssh_session(
                stream,
                &tunnel.username,
                &tunnel.auth,
                tunnel.strict_host_key,
                tunnel.host_key.as_deref(),
            )?;
            let channel = sess
                .channel_direct_tcpip(&tunnel.target_host, tunnel.target_port, None)
                .map_err(|e| ProxyError::ssh("failed to open SSH direct-tcpip channel", e))?;
            Ok(TunneledStream {
                stream: HopStream::Ssh(channel),
                session: Some(sess),
            })
        }
        ResolvedTransport::Chain(chain) => {
            if chain.hops.is_empty() {
                return Err(ProxyError::protocol("proxy chain has no hops"));
            }

            let mut final_session = None;

            // Connect to first hop
            let mut current_stream = match &chain.hops[0].config {
                ResolvedProxyHopConfig::Socks5 { host, port, auth } => {
                    let stream = std::net::TcpStream::connect((host.as_str(), *port))
                        .map_err(|e| ProxyError::io("chain hop 0 (SOCKS5) connection failed", e))?;
                    let auth_creds = auth
                        .as_ref()
                        .map(|a| (a.username.as_str(), a.password.as_str()));
                    let next_hop = chain
                        .hops
                        .get(1)
                        .ok_or_else(|| ProxyError::protocol("chain hop 0 needs subsequent hop"))?;
                    let (next_host, next_port) = match &next_hop.config {
                        ResolvedProxyHopConfig::Socks5 { host, port, .. } => (host.as_str(), *port),
                        ResolvedProxyHopConfig::HttpConnect { host, port, .. } => {
                            (host.as_str(), *port)
                        }
                        ResolvedProxyHopConfig::Ssh {
                            ssh_host, ssh_port, ..
                        } => (ssh_host.as_str(), *ssh_port),
                    };
                    let stream = socks5_handshake_sync(stream, next_host, next_port, auth_creds)
                        .map_err(|e| e.context("chain hop 0 (SOCKS5) handshake failed"))?;
                    HopStream::Tcp(stream)
                }
                ResolvedProxyHopConfig::HttpConnect { host, port, auth } => {
                    let stream = std::net::TcpStream::connect((host.as_str(), *port))
                        .map_err(|e| ProxyError::io("chain hop 0 (HTTP) connection failed", e))?;
                    let auth_creds = auth
                        .as_ref()
                        .map(|a| (a.username.as_str(), a.password.as_str()));
                    let next_hop = chain
                        .hops
                        .get(1)
                        .ok_or_else(|| ProxyError::protocol("chain hop 0 needs subsequent hop"))?;
                    let (next_host, next_port) = match &next_hop.config {
                        ResolvedProxyHopConfig::Socks5 { host, port, .. } => (host.as_str(), *port),
                        ResolvedProxyHopConfig::HttpConnect { host, port, .. } => {
                            (host.as_str(), *port)
                        }
                        ResolvedProxyHopConfig::Ssh {
                            ssh_host, ssh_port, ..
                        } => (ssh_host.as_str(), *ssh_port),
                    };
                    let stream =
                        http_connect_handshake_sync(stream, next_host, next_port, auth_creds)
                            .map_err(|e| e.context("chain hop 0 (HTTP) CONNECT failed"))?;
                    HopStream::Tcp(stream)
                }
                ResolvedProxyHopConfig::Ssh {
                    ssh_host,
                    ssh_port,
                    username,
                    auth,
                    strict_host_key,
                    host_key,
                } => {
                    let stream = std::net::TcpStream::connect((ssh_host.as_str(), *ssh_port))
                        .map_err(|e| ProxyError::io("chain hop 0 (SSH) connection failed", e))?;
                    let sess = establish_ssh_session(
                        stream,
                        username,
                        auth,
                        *strict_host_key,
                        host_key.as_deref(),
                    )?;
                    let next_hop = chain
                        .hops
                        .get(1)
                        .ok_or_else(|| ProxyError::protocol("chain hop 0 needs subsequent hop"))?;
                    let (next_host, next_port) = match &next_hop.config {
                        ResolvedProxyHopConfig::Socks5 { host, port, .. } => (host.as_str(), *port),
                        ResolvedProxyHopConfig::HttpConnect { host, port, .. } => {
                            (host.as_str(), *port)
                        }
                        ResolvedProxyHopConfig::Ssh {
                            ssh_host, ssh_port, ..
                        } => (ssh_host.as_str(), *ssh_port),
                    };
                    let channel = sess
                        .channel_direct_tcpip(next_host, next_port, None)
                        .map_err(|e| {
                            ProxyError::ssh("failed to open SSH channel for next hop", e)
                        })?;
                    final_session = Some(sess);
                    HopStream::Ssh(channel)
                }
            };

            // Loop remaining hops
            for i in 1..chain.hops.len() {
                let hop = &chain.hops[i];
                let is_last = i == chain.hops.len() - 1;

                let (target_host, target_port) = if is_last {
                    (chain.target_host.as_str(), chain.target_port)
                } else {
                    match &chain.hops[i + 1].config {
                        ResolvedProxyHopConfig::Socks5 { host, port, .. } => (host.as_str(), *port),
                        ResolvedProxyHopConfig::HttpConnect { host, port, .. } => {
                            (host.as_str(), *port)
                        }
                        ResolvedProxyHopConfig::Ssh {
                            ssh_host, ssh_port, ..
                        } => (ssh_host.as_str(), *ssh_port),
                    }
                };

                match &hop.config {
                    ResolvedProxyHopConfig::Socks5 { auth, .. } => {
                        let auth_creds = auth
                            .as_ref()
                            .map(|a| (a.username.as_str(), a.password.as_str()));
                        current_stream = socks5_handshake_sync(
                            current_stream,
                            target_host,
                            target_port,
                            auth_creds,
                        )
                        .map_err(|e| {
                            e.context(format!("chain hop {i} (SOCKS5) handshake failed"))
                        })?;
                    }
                    ResolvedProxyHopConfig::HttpConnect { auth, .. } => {
                        let auth_creds = auth
                            .as_ref()
                            .map(|a| (a.username.as_str(), a.password.as_str()));
                        current_stream = http_connect_handshake_sync(
                            current_stream,
                            target_host,
                            target_port,
                            auth_creds,
                        )
                        .map_err(|e| e.context(format!("chain hop {i} (HTTP) CONNECT failed")))?;
                    }
                    ResolvedProxyHopConfig::Ssh {
                        username,
                        auth,
                        strict_host_key,
                        host_key,
                        ..
                    } => {
                        let tcp_stream = match current_stream {
                            HopStream::Tcp(s) => s,
                            HopStream::Ssh(_) => {
                                return Err(ProxyError::protocol(format!("chain hop {i} (SSH) cannot be nested inside another SSH channel (not supported by libssh2 Rust bindings)")));
                            }
                        };
                        let sess = establish_ssh_session(
                            tcp_stream,
                            username,
                            auth,
                            *strict_host_key,
                            host_key.as_deref(),
                        )?;
                        let channel = sess
                            .channel_direct_tcpip(target_host, target_port, None)
                            .map_err(|e| {
                                ProxyError::ssh("failed to open SSH channel for hop", e)
                            })?;
                        final_session = Some(sess);
                        current_stream = HopStream::Ssh(channel);
                    }
                }
            }

            Ok(TunneledStream {
                stream: current_stream,
                session: final_session,
            })
        }
    }
}
