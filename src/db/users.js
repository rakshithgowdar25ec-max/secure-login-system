const db = require("./db");

const insertUser = db.prepare(`
  INSERT INTO users (username, email, password_hash)
  VALUES (@username, @email, @password_hash)
`);

const findByUsername = db.prepare(`SELECT * FROM users WHERE username = ?`);
const findByEmail = db.prepare(`SELECT * FROM users WHERE email = ?`);
const findById = db.prepare(`SELECT * FROM users WHERE id = ?`);

const updatePasswordHash = db.prepare(`
  UPDATE users SET password_hash = ? WHERE id = ?
`);

const setTwoFactorSecret = db.prepare(`
  UPDATE users SET twofa_secret = ? WHERE id = ?
`);

const enableTwoFactor = db.prepare(`
  UPDATE users SET twofa_enabled = 1 WHERE id = ?
`);

const disableTwoFactor = db.prepare(`
  UPDATE users SET twofa_enabled = 0, twofa_secret = NULL WHERE id = ?
`);

const recordFailedAttempt = db.prepare(`
  UPDATE users SET failed_attempts = failed_attempts + 1 WHERE id = ?
`);

const resetFailedAttempts = db.prepare(`
  UPDATE users SET failed_attempts = 0, lockout_until = NULL WHERE id = ?
`);

const setLockout = db.prepare(`
  UPDATE users SET lockout_until = ? WHERE id = ?
`);

module.exports = {
  createUser({ username, email, password_hash }) {
    return insertUser.run({ username, email, password_hash });
  },
  getByUsername(username) {
    return findByUsername.get(username);
  },
  getByEmail(email) {
    return findByEmail.get(email);
  },
  getById(id) {
    return findById.get(id);
  },
  updatePassword(id, password_hash) {
    return updatePasswordHash.run(password_hash, id);
  },
  setTwoFactorSecret(id, secret) {
    return setTwoFactorSecret.run(secret, id);
  },
  enableTwoFactor(id) {
    return enableTwoFactor.run(id);
  },
  disableTwoFactor(id) {
    return disableTwoFactor.run(id);
  },
  recordFailedAttempt(id) {
    return recordFailedAttempt.run(id);
  },
  resetFailedAttempts(id) {
    return resetFailedAttempts.run(id);
  },
  setLockout(id, timestampMs) {
    return setLockout.run(timestampMs, id);
  },
};
