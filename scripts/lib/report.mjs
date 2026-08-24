/**
 * The one output shape every check in this directory speaks.
 *
 * Each script used to carry its own `fail()` and prefix its own `console.log`
 * lines by hand, which is how two of them drifted into printing the same
 * finding in two different formats. A reporter binds the prefix once.
 */

/** `  - a\n  - b`, the list form every check uses for findings. */
export function bullets(items) {
  return items.map((item) => `  - ${item}`).join("\n");
}

/**
 * A reporter for one check, named by the prefix it stamps on every line.
 *
 * `fail` and `skip` exit the process, so callers can treat them as terminal
 * and keep the happy path unindented.
 */
export function reporter(prefix) {
  const line = (message) => `${prefix}: ${message}`;
  return {
    prefix,

    /** Report a fatal problem and exit non-zero. Never returns. */
    fail(message) {
      console.error(line(message));
      process.exit(1);
    },

    /** Report a finding without exiting, so several can be shown at once. */
    problem(title, items, advice) {
      console.error(`${line(title)}:\n${bullets(items)}\n\n${advice}`);
    },

    /** Report success. */
    ok(message) {
      console.log(line(message));
    },

    /** Report that there is nothing to check here and exit zero. Never returns. */
    skip(message) {
      console.log(line(message));
      process.exit(0);
    },
  };
}
