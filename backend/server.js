require('dotenv').config();
const fs = require("fs");
const https = require("https");
const express = require("express");
const helmet = require("helmet");
const cookieParser = require('cookie-parser');
const session = require("express-session");
const cors = require('cors');
const passport = require("passport");
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const csrf = require('csurf');

const app = express();
app.use(express.json());

// ----- CORS -----
app.use(cors({
  origin: ['http://localhost:3000', 'https://localhost:3000'],
  credentials: true,
  methods: ['GET','POST','PUT','PATCH','DELETE','OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'x-csrf-token'],
}));

// ----- Cookies & Session  -----
app.use(cookieParser());

app.use(session({
  name: 'sid',
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    secure: true,                // HTTPS only
    sameSite: 'none',            // cross-site (3000 -> 3001)
    maxAge: 15 * 1000       // 15 minutes idle timeout
  },
  rolling: true                  // sliding expiration
}));

// Absolute session lifetime (e.g., 8 hours)
const ABSOLUTE_MS = 8 * 60 * 60 * 1000;
app.use((req, res, next) => {
  if (!req.session.createdAt) req.session.createdAt = Date.now();
  if (Date.now() - req.session.createdAt > ABSOLUTE_MS) {
    req.session.destroy(() => res.status(440).json({ error: 'Session expired' }));
  } else {
    next();
  }
});

// ----- Request logger -----
app.use((req, res, next) => {
  console.log(`[${new Date().toISOString()}] ${req.method} ${req.path}`);
  next();
});

// ----- Helmet -----
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "https://cdn.jsdelivr.net"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", "data:", "https:"],
      connectSrc: ["'self'"], 
    },
  },
  frameguard: { action: "deny" },
  hidePoweredBy: true,
  noSniff: true,
  hsts: { maxAge: 31536000 },
}));

// ----- In-memory users (demo) -----
const users = new Map();

// ----- Passport (after session) -----
app.use(passport.initialize());
app.use(passport.session());

passport.use(new GoogleStrategy(
  {
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: "https://localhost:3001/auth/google/callback"
  },
  (accessToken, refreshToken, profile, done) => {
    const user = {
      id: profile.id,
      displayName: profile.displayName,
      email: profile.emails?.[0]?.value,
      photo: profile.photos?.[0]?.value
    };
    users.set(profile.id, user);
    return done(null, user);
  }
));

passport.serializeUser((user, done) => done(null, user.id));
passport.deserializeUser((id, done) => done(null, users.get(id) || null));

// ----- CSRF  -----
const csrfProtection = csrf({
  cookie: {
    httpOnly: true,
    secure: true,
    sameSite: 'none'
  }
});
app.use(csrfProtection);

// Expose token
app.get('/csrf-token', (req, res) => {
  res.json({ csrfToken: req.csrfToken() });
});

// CSRF error handler
app.use((err, req, res, next) => {
  if (err.code === 'EBADCSRFTOKEN') {
    return res.status(403).json({ error: 'Invalid CSRF token' });
  }
  return next(err);
});

/* ------------------- AUTH ROUTES ------------------- */

app.get("/auth/google",
  passport.authenticate("google", { scope: ["profile", "email"] })
);

app.get("/auth/google/callback", (req, res, next) => {
  passport.authenticate("google", (err, user) => {
    if (err || !user) return res.redirect("/auth/failure");
    req.logIn(user, (e) => {
      if (e) return res.redirect("/auth/failure");
      // After login, a Set-Cookie: sid=... should be present
      return res.redirect("https://localhost:3000");
    });
  })(req, res, next);
});

app.get("/auth/failure", (req, res) => {
  res.status(401).send("Google authentication failed.");
});

// Session check
app.get("/auth/me", (req, res) => {
  if (!req.user) return res.status(401).json({ user: null });
  res.json({ user: req.user });
});

// Logout
app.post("/auth/logout", (req, res) => {
  req.logout(() => {
    req.session.destroy(() => {
      res.clearCookie("sid", { path: '/', secure: true, sameSite: 'none' }); // <-- matches cookie name
      res.json({ message: "Logged out" });
    });
  });
});

/* ------------------- API ROUTES ------------------- */

app.get('/posts', (req, res) => {
  res.set('Cache-Control', 'public, max-age=300, stale-while-revalidate=600');
  res.json({ posts: ["Post 1", "Post 2"] });
});

app.get('/posts/:id', (req, res) => {
  res.set('Cache-Control', 'public, max-age=300');
  res.json({ id: req.params.id, content: "This is a single post." });
});

app.post('/posts', (req, res) => {
  res.set('Cache-Control', 'no-store');
  res.json({ message: "Post created successfully!" });
});

app.get('/profile/:username', (req, res) => {
  res.set('Cache-Control', 'private, max-age=120');
  res.json({ username: req.params.username, bio: "Developer bio" });
});

app.post('/contact', (req, res) => {
  res.set('Cache-Control', 'no-store');
  res.json({ message: "Your message has been sent!" });
});

// Optional root
app.get("/", (req, res) => {
  res.send("This is the HTTPS server");
});

// ----- HTTPS server -----
const options = {
  key: fs.readFileSync("key.pem"),
  cert: fs.readFileSync("cert.pem")
};

https.createServer(options, app).listen(3001, () => {
  console.log("HTTPS server running at https://localhost:3001");
});
