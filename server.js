require("dotenv").config();

const path = require("path");
const express = require("express");
const session = require("express-session");
const SQLiteStore = require("connect-sqlite3")(session);
const helmet = require("helmet");

require("./src/db/db"); // ensures schema exists before routes load
const authRoutes = require("./src/routes/authRoutes");
const { ensureCsrfToken } = require("./src/middleware/auth");

const app = express();
const PORT = process.env.PORT || 3000;
const isProd = process.env.NODE_ENV === "production";

if (!process.env.SESSION_SECRET) {
  console.error(
    "FATAL: SESSION_SECRET is not set. Copy .env.example to .env and set a random secret before starting."
  );
  process.exit(1);
}

// Security headers (CSP, X-Frame-Options, HSTS in prod, etc.)
app.use(helmet());

app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));
app.use(express.static(path.join(__dirname, "public")));

app.use(express.urlencoded({ extended: false }));
app.use(express.json());

app.use(
  session({
    store: new SQLiteStore({ db: "sessions.db", dir: path.join(__dirname, "db") }),
    name: "connect.sid",
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true, // JS on the page can't read the cookie (mitigates XSS token theft)
      secure: isProd, // only sent over HTTPS in production
      sameSite: "lax", // mitigates CSRF from cross-site requests
      maxAge: 1000 * 60 * 60 * 2, // 2 hour session lifetime
    },
  })
);

app.use(ensureCsrfToken);

app.use("/", authRoutes);

app.get("/", (req, res) => {
  res.redirect(req.session.userId ? "/dashboard" : "/login");
});

app.use((req, res) => {
  res.status(404).render("error", { message: "Page not found" });
});

// Centralized error handler — never leak stack traces to the client.
app.use((err, req, res, next) => {
  console.error(err);
  res.status(500).render("error", { message: "Something went wrong. Please try again." });
});

app.listen(PORT, () => {
  console.log(`Secure login app running at http://localhost:${PORT}`);
});
