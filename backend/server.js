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

const crypto = require("crypto");
const { body, validationResult } = require("express-validator");
const escapeHtml = require("escape-html");

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
    maxAge: 15 * 60 * 1000       // 15 minutes idle timeout
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
app.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        // Default rule
        defaultSrc: ["'self'"],

        // Resources
        scriptSrc: ["'self'", "https://cdn.jsdelivr.net"],
        styleSrc: ["'self'"],
        imgSrc: ["'self'", "data:"],
        connectSrc: ["'self'"],

        // ✅ REQUIRED: These directives have NO fallback
        frameAncestors: ["'none'"],  // prevents clickjacking / iframe embedding
        formAction: ["'self'"],      // only allow form submissions to your own domain
        objectSrc: ["'none'"],       // block <object>, <embed>, <applet>
        baseUri: ["'self'"],         // restricts <base> tag manipulation
      },
    },

    frameguard: { action: "deny" }, // still okay, works with frameAncestors
    hidePoweredBy: true,
    noSniff: true,
    hsts: { maxAge: 31536000 },
  })
);


// ----- In-memory users (demo) -----
const users = new Map();

function requireAuth(req, res, next) {
  if (!req.user) {
    return res.status(401).json({ error: "Not authenticated" });
  }
  next();
}

// ----- Simple encryption helpers for sensitive fields -----
const ENC_ALGO = "aes-256-gcm";
// 32-byte key derived from secret in .env
const ENC_KEY = crypto
  .createHash("sha256")
  .update(String(process.env.ENCRYPTION_SECRET || "fallback-secret"))
  .digest();

function encrypt(text) {
  if (!text) return "";
  const iv = crypto.randomBytes(12); // GCM recommended IV length
  const cipher = crypto.createCipheriv(ENC_ALGO, ENC_KEY, iv);
  const encrypted = Buffer.concat([cipher.update(text, "utf8"), cipher.final()]);
  const tag = cipher.getAuthTag();
  // store iv + tag + encrypted in base64
  return Buffer.concat([iv, tag, encrypted]).toString("base64");
}

function decrypt(payload) {
  if (!payload) return "";
  try {
    const buf = Buffer.from(payload, "base64");
    const iv = buf.subarray(0, 12);
    const tag = buf.subarray(12, 28);
    const data = buf.subarray(28);
    const decipher = crypto.createDecipheriv(ENC_ALGO, ENC_KEY, iv);
    decipher.setAuthTag(tag);
    const decrypted = Buffer.concat([decipher.update(data), decipher.final()]);
    return decrypted.toString("utf8");
  } catch {
    return "";
  }
}


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
    const existing = users.get(profile.id);
    const emailPlain = profile.emails?.[0]?.value || "";

    const user = existing || {
      id: profile.id,
      displayName: profile.displayName,
      encryptedBio: encrypt(""), // default empty bio
    };

    // Always (re)store encrypted email
    user.encryptedEmail = emailPlain ? encrypt(emailPlain) : user.encryptedEmail;

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

  const dbUser = users.get(req.user.id);
  if (!dbUser) return res.status(401).json({ user: null });

  const email = decrypt(dbUser.encryptedEmail);
  const bio = decrypt(dbUser.encryptedBio);

  res.json({
    user: {
      id: dbUser.id,
      displayName: dbUser.displayName,
      email,
      bio,
    },
  });
});

// Get current user's profile (decrypted)
app.get("/profile/me", requireAuth, (req, res) => {
  const dbUser = users.get(req.user.id);
  if (!dbUser) return res.status(404).json({ error: "User not found" });

  const email = decrypt(dbUser.encryptedEmail);
  const bio = decrypt(dbUser.encryptedBio);

  res.json({
    profile: {
      name: dbUser.displayName || "",
      email,
      bio,
    },
  });
});

// Update profile with validation + sanitization + encryption
app.post(
  "/profile",
  requireAuth,
  [
    body("name")
      .trim()
      .isLength({ min: 3, max: 50 })
      .matches(/^[A-Za-z\s]+$/) // alphabetic + spaces
      .withMessage("Name must be 3–50 letters only.")
      .escape(), // sanitize

    body("email")
      .trim()
      .isEmail()
      .withMessage("Must be a valid email address.")
      .normalizeEmail(),

    body("bio")
      .trim()
      .isLength({ max: 500 })
      // allow letters, numbers, spaces and basic punctuation; no < > etc.
      .matches(/^[A-Za-z0-9\s.,!?'"-]*$/)
      .withMessage(
        "Bio can have up to 500 characters, no HTML tags or special characters."
      ),
  ],
  (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const dbUser = users.get(req.user.id);
    if (!dbUser) return res.status(404).json({ error: "User not found" });

    // Extract sanitized values
    const { name, email, bio } = req.body;

    // Escape again before storage to be extra safe (defense-in-depth)
    const safeName = escapeHtml(name);
    const safeEmail = escapeHtml(email);
    const safeBio = escapeHtml(bio);

    // Encrypt sensitive fields before storing
    dbUser.displayName = safeName;
    dbUser.encryptedEmail = encrypt(safeEmail);
    dbUser.encryptedBio = encrypt(safeBio);

    users.set(dbUser.id, dbUser);

    res.json({
      message: "Profile updated",
      profile: {
        name: safeName,
        email: safeEmail,
        bio: safeBio,
      },
    });
  }
);



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
