const crypto = require("crypto");

function requireAuth(req, res, next) {
  if (req.session && req.session.userId) {
    return next();
  }
  return res.redirect("/login");
}

function requireGuest(req, res, next) {
  if (req.session && req.session.userId) {
    return res.redirect("/dashboard");
  }
  return next();
}

function requirePendingTwoFactor(req, res, next) {
  if (req.session && req.session.pendingUserId) {
    return next();
  }
  return res.redirect("/login");
}

function ensureCsrfToken(req, res, next) {
  if (!req.session.csrfToken) {
    req.session.csrfToken = crypto.randomBytes(32).toString("hex");
  }
  res.locals.csrfToken = req.session.csrfToken;
  next();
}

function verifyCsrfToken(req, res, next) {
  const submitted = req.body._csrf;
  if (!submitted || submitted !== req.session.csrfToken) {
