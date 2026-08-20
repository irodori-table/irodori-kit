/**
 * Identifier fragments whose presence in connector Rust sources counts as
 * evidence that an authentication method is wired up.
 *
 * Deliberately generous: this catches declarations with nothing behind them;
 * the field-binding guard separately checks the individual values a declared,
 * implemented method asks the host to collect. `"*"` needs no driver evidence.
 */
export const AUTH_EVIDENCE = Object.freeze({
  none: ["*"],
  customDriverOptions: ["*"],
  connectionString: ["connectionString", "dsn", "url"],

  basic: ["password"],
  userPassword: ["password"],
  sqlPassword: ["password"],
  scram: ["password"],
  saslPlain: ["password"],
  saslScram: ["scram", "sasl"],
  srp: ["password"],
  aclUserPassword: ["password"],

  apiKey: ["apiKey", "api_key"],
  jwt: ["jwt"],
  bearerToken: ["bearerToken", "bearer"],
  accessToken: ["accessToken"],
  restToken: ["restToken", "token"],
  redisToken: ["redisToken", "token"],
  pluginToken: ["pluginToken"],
  catalogBearerToken: ["catalogBearerToken", "catalogToken"],
  catalogPassword: ["catalogPassword"],

  // A bare oauth2/clientSecret spelling can credit a forwarded token or an
  // Azure service principal. Grant machinery is the recoverable proof.
  oauth2: [
    "grant_type",
    "oauth2ServerUri",
    "oauthServerUri",
    "oauth2ClientSecret",
    "oauthClientSecret",
    "tokenEndpoint",
    "token_endpoint",
  ],
  oauthAccessToken: ["oauthAccessToken"],
  oidc: ["oidc"],
  saml: ["saml"],
  ldap: ["ldap"],
  kerberos: ["kerberos", "gssapi", "krb"],
  externalBrowser: ["externalBrowser", "browser"],
  browserSso: ["browserSso", "browser"],
  windowsIntegrated: ["integratedSecurity", "ntlm", "windowsIntegrated"],
  clientCertificate: [
    "clientCert",
    "client_cert",
    "certPath",
    "sslCert",
    "tlsCert",
  ],
  mongodbX509: ["x509", "X509"],

  awsIam: ["awsIam", "MONGODB-AWS", "awsAccessKey"],
  awsSigV4: ["sigv4", "SigV4", "signRequest", "awsAccessKey"],
  awsProfile: [
    "awsProfile",
    "AWS_PROFILE",
    "profile_name",
    "from_profile",
    "credentials_file",
  ],
  awsSso: ["awsSso", "ssoStart", "credential_chain"],
  awsAssumeRole: ["assumeRole", "roleArn", "AssumeRole"],
  awsDefaultCredentialsChain: [
    "defaultCredentialsChain",
    "credentialsChain",
    "credential_chain",
    "awsProfile",
  ],
  webIdentity: [
    "webIdentity",
    "WebIdentity",
    "web_identity",
    "credential_chain",
  ],
  sessionToken: ["sessionToken", "securityToken"],

  serviceAccountJson: ["serviceAccountJson", "credentialsJson"],
  serviceAccountJwt: ["privateKey", "serviceAccountJwt"],
  serviceAccountImpersonation: ["impersonat"],
  googleApplicationDefaultCredentials: [
    "applicationDefault",
    "GOOGLE_APPLICATION_CREDENTIALS",
    "adc",
  ],
  workloadIdentity: ["workloadIdentity", "workload_identity"],

  azureAd: [
    "azureAd",
    "azure_ad",
    "AzureAD",
    "azureCredentialChain",
    "aadToken",
    "entraToken",
    "azureAccessToken",
    "azureTenantId",
  ],
  servicePrincipal: ["servicePrincipal", "tenantId"],
  servicePrincipalCertificate: [
    "servicePrincipalCertificate",
    "CLIENT_CERTIFICATE_PATH",
  ],
  managedIdentity: ["managedIdentity", "managed_identity"],
  sasToken: ["sasToken"],

  databricksPersonalAccessToken: ["pat", "accessToken"],
  databricksOAuthToken: ["oauthToken"],
  databricksOAuthU2M: ["u2m", "oauthU2M"],
  databricksOAuthM2M: ["m2m", "oauthM2M", "clientSecret"],
  databricksAzureManagedIdentity: ["managedIdentity"],

  snowflakeKeyPair: ["privateKey", "keyPair"],
  snowflakeProgrammaticAccessToken: ["programmaticAccessToken", "pat"],
  snowflakeSessionToken: ["sessionToken"],
  snowflakeWorkloadIdentity: ["workloadIdentity"],

  motherduckToken: ["motherduckToken", "motherduck_token"],
  extensionCredential: ["CREATE SECRET", "createSecret", "credential"],
  oracleWallet: ["wallet"],
  cloudIamToken: ["cloudIamToken", "iamToken"],
});

export function authMethodImplemented(methodId, source) {
  const evidence = AUTH_EVIDENCE[methodId];
  if (!evidence) {
    return null;
  }
  return (
    evidence.includes("*") || evidence.some((fragment) => source.includes(fragment))
  );
}

export function analyzeAuthMethods(config, source) {
  const declared = (config.connector?.connection?.authMethods ?? []).map(
    (method) => method.id,
  );
  const unknown = declared.filter((id) => !(id in AUTH_EVIDENCE));
  const unimplemented = declared.filter(
    (id) => authMethodImplemented(id, source) === false,
  );
  return { declared, unknown, unimplemented };
}
