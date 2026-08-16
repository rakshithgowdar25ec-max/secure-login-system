const express = require("express");
const bcrypt = require("bcryptjs");
const speakeasy = require("speakeasy");
const QRCode = require("qrcode");
const { body, validationResult } = require("express-validator");

const users = require("../db/users");
const {
  requireAuth,
  requireGuest,
  requirePendingTwoFactor,
  verifyCsrfToken,
} = require("../middleware/auth");
const { loginLimiter, registerLimiter } = require("../middleware/rateLimiters");

const router = express.Router();

const BCRYPT_COST = 12;
const MAX_FAILED_ATTEMPTS = 5;
const LOCKOUT_DURATION_MS = 15 * 60 * 1000;

const registerValidation = [
  body("username")
    .trim()
    .isLength({ min: 3, max: 20 })
    .withMessage("Username must be 3-20 characters")
    .matches(/^[a-zA-Z0-9_]+$/)
    .withMessage("Username may only contain letters, numbers, and underscores"),
  body("email").trim().isEmail().withMessage("Enter a valid email address").normalizeEmail(),
  body("password")
    .isLength({ min: 8 })
    .withMessage("Password must be at least 8 characters")
    .matches(/[a-z]/)
    .withMessage("Password must include a lowercase letter")
    .matches(/[A-Z]/)
    .withMessage("Password must include an uppercase letter")
    .matches(/[0-9]/)
    .withMessage("Password must include a number"),
  body("confirmPassword").custom((value, { req }) => {
    if (value !== req.body.password) {
      throw new Error("Passwords do not match");
    }
    return true;
  }),
];

const loginValidation = [
  body("username").trim().notEmpty().withMessage("Username is required"),
  body("password").notEmpty().withMessage("Password is required"),
];

router.get("/register", requireGuest, (req, res) => {
  res.render("register", { errors: [], old: {} });
});

router.post("/register", requireGuest, verifyCsrfToken, registerLimiter, registerValidation, async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).render("register", {
      errors: errors.array(),
      old: { username: req.body.username, email: req.body.email },
    });
  }

  const { username, email, password } = req.body;

  if (users.getByUsername(username)) {
    return res.status(400).render("register", {
      errors: [{ msg: "That username is already taken" }],
      old: { username, email },
    });
  }
  if (users.getByEmail(email)) {
    return res.status(400).render("register", {
      errors: [{ msg: "That email is already registered" }],
      old: { username, email },
    });
  }

  const password_hash = await bcrypt.hash(password, BCRYPT_COST);
  users.createUser({ username, email, password_hash });

  res.redirect("/login?registered=1");
});

router.get("/login", requireGuest, (req, res) => {
  res.render("login", {
    errors: [],
    registered: req.query.registered === "1",
  });
});

router.post("/login", requireGuest, verifyCsrfToken, loginLimiter, loginValidation, async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).render("login", { errors: errors.array(), registered: false });
  }

  const { username, password } = req.body;
  const user = users.getByUsername(username);

  const genericError = [{ msg: "Invalid username or password" }];

  if (!user) {
    await bcrypt.compare(password, "$2a$12$invalidsaltinvalidsaltinvalidsalt.");
    return res.status(400).render("login", { errors: genericError, registered: false });
  }

  if (user.lockout_until && user.lockout_until > Date.now()) {
    const minutesLeft = Math.ceil((user.lockout_until - Date.now()) / 60000);
    return res.status(423).render("login", {
      errors: [{ msg: `Account temporarily locked. Try again in ${minutesLeft} minute(s).` }],
      registered: false,
    });
  }

  const passwordOk = await bcrypt.compare(password, user.password_hash);

  if (!passwordOk) {
    users.recordFailedAttempt(user.id);
    const attempts = user.failed_attempts + 1;
    if (attempts >= MAX_FAILED_ATTEMPTS) {
      users.setLockout(user.id, Date.now() + LOCKOUT_DURATION_MS);
    }
    return res.status(400).render("login", { errors: genericError, registered: false });
  }

  users.resetFailedAttempts(user.id);

  if (user.twofa_enabled) {
    req.session.pendingUserId = user.id;
    return res.redirect("/login/2fa");
  }

  req.session.regenerate((err) => {
    if (err) return res.status(500).render("error", { message: "Login failed, please try again." });
    req.session.userId = user.id;
    req.session.username = user.username;
    res.redirect("/dashboard");
  });
});

router.get("/login/2fa", requirePendingTwoFactor, (req, res) => {
  res.render("login-2fa", { errors: [] });
});

router.post(
  "/login/2fa",
  requirePendingTwoFactor,
  verifyCsrfToken,
  loginLimiter,
  body("token").trim().isLength({ min: 6, max: 6 }).isNumeric(),
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).render("login-2fa", { errors: [{ msg: "Enter the 6-digit code" }] });
    }

    const user = users.getById(req.session.pendingUserId);
    if (!user) {
      req.session.pendingUserId = null;
      return res.redirect("/login");
    }

    const verified = speakeasy.totp.verify({
      secret: user.twofa_secret,
      encoding: "base32",
      token: req.body.token,
      window: 1,
    });

    if (!verified) {
      return res.status(400).render("login-2fa", { errors: [{ msg: "Invalid or expired code" }] });
    }

    const userId = user.id;
    const username = user.username;

    req.session.regenerate((err) => {
      if (err) return res.status(500).render("error", { message: "Login failed, please try again." });
      req.session.userId = userId;
      req.session.username = username;
      res.redirect("/dashboard");
    });
  }
);

router.post("/logout", requireAuth, verifyCsrfToken, (req, res) => {
  req.session.destroy((err) => {
    res.clearCookie("connect.sid");
    res.redirect("/login");
  });
});

router.get("/dashboard", requireAuth, (req, res) => {
  const user = users.getById(req.session.userId);
  res.render("dashboard", { user });
});

router.get("/2fa/setup", requireAuth, async (req, res) => {
  const user = users.getById(req.session.userId);
  if (user.twofa_enabled) {
    return res.redirect("/dashboard");
  }

  const secret = speakeasy.generateSecret({
    name: `SecureLoginApp (${user.username})`,
  });
  req.session.pendingTwoFactorSecret = secret.base32;

  const qrDataUrl = await QRCode.toDataURL(secret.otpauth_url);
  res.render("2fa-setup", { qrDataUrl, manualKey: secret.base32, errors: [] });
});

router.post(
  "/2fa/setup",
  requireAuth,
  verifyCsrfToken,
  body("token").trim().isLength({ min: 6, max: 6 }).isNumeric(),
  async (req, res) => {
    const secret = req.session.pendingTwoFactorSecret;
    const errors = validationResult(req);

    if (!secret) {
      return res.redirect("/2fa/setup");
    }
    if (!errors.isEmpty()) {
      const qrDataUrl = await QRCode.toDataURL(
        speakeasy.otpauthURL({ secret, label: "SecureLoginApp", encoding: "base32" })
      );
      return res.status(400).render("2fa-setup", {
        qrDataUrl,
        manualKey: secret,
        errors: [{ msg: "Enter the 6-digit code from your authenticator app" }],
      });
    }

    const verified = speakeasy.totp.verify({
      secret,
      encoding: "base32",
      token: req.body.token,
      window: 1,
    });

    if (!verified) {
      const qrDataUrl = await QRCode.toDataURL(
        speakeasy.otpauthURL({ secret, label: "SecureLoginApp", encoding: "base32" })
      );
      return res.status(400).render("2fa-setup", {
        qrDataUrl,
        manualKey: secret,
        errors: [{ msg: "That code didn't match. Please try again." }],
      });
    }

    users.setTwoFactorSecret(req.session.userId, secret);
    users.enableTwoFactor(req.session.userId);
    req.session.pendingTwoFactorSecret = null;

    res.redirect("/dashboard?2fa=enabled");
  }
);

router.post("/2fa/disable", requireAuth, verifyCsrfToken, (req, res) => {
  users.disableTwoFactor(req.session.userId);
  res.redirect("/dashboard?2fa=disabled");
});

module.exports = router;
