
This is a simple portfolio application for users to showcase their work, network and blog.

Setup instructions:
1. Clone the repository: (https://github.com/jacquebento/PorfolioApp_phase2.git)
2. Install dependencies: npm install
3. In the project directory run: cd backend node server.js
4. Open (https://localhost:3001) to accept the cert
5. On a second terminal in the project directory run: cd frontend npm start
6. Open (http://localhost:3000) to view it in your browser

SSL configuration:
1. Generate private key: openssl genrsa -out key.pem 2048
file created: key.pem - location: project root
2. Create a Certificate Signing Request (CSR): openssl req -new -key key.pem -out cert.csr
answer the questions:
for Common Name (CN) → use localhost
file created: cert.csr - location: project root
3. Generate a self-signed certificate: openssl x509 -req -days 365 -in cert.csr -signkey key.pem -out cert.pem
file created: cert.pem - location: project root
4. make sure your keys are loaded in the server.js file:
const options = {
  key: fs.readFileSync("key.pem"),
  cert: fs.readFileSync("cert.pem")
};
5. access backend first via https://localhost:3001 to accept the cert
Tips:
- it's normal for the browser show a warning "Not secure" because it's a self-signed certificate
- be aware that self-signed certs are valid for 1 year

Security headers using helmet:
- Content-Security-Policy → restricts sources of scripts, styles, and images
- X-Frame-Options → prevents clickjacking
- X-Content-Type-Options → stops MIME-type sniffing
- Strict-Transport-Security (HSTS) → enforces HTTPS
- X-XSS-Protection → basic XSS filtering
- Hide X-Powered-By → hides Express signature

Routes and Caching strategies:
- GET /posts to return all blog posts (5 minutes cache) - Cache-Control: public, max-age=300, stale-while-revalidate=600
- GET /posts/:id to fetch a single post (5 minutes cache) - Cache-Control: public, max-age=300
- POST /posts to create a new post (no cache) - Cache-Control - no-store
- GET /profile/:username to display profile (2 minutes cache) - Cache-Control: public, max-age=120
- POST /contact to submit contact message (no cache) - Cache-Control - no-store

Lessons Learned:
I chose OpenSSL because we had already used this method in a classroom lab, and it was the only experience I had with this process. After researching, I discovered that because it's open-source, it can be used widely.

Choosing which headers to use was challenging because it required some research. I chose headers that control what the browser is allowed to load, forcing the browser to only use HTTPS connections for a certain period of time, and enabling filters.

I configured the GET/posts route cache strategy so that only non-sensitive data should be cached, the GET /posts/:id to apply role-based access if post is sensitive, the POST /posts to require authentication and sanitize input, the GET /profile/:username to only public info cached; private info not cached and the POST /contact to validate input, preventing spam.

Authentication and Session Management
The application uses Google OAuth 2.0 for authentication, allowing users to securely log in with their Google accounts. After successful login, an Express session is created and stored in a Secure, HttpOnly cookie to prevent client-side access. Sessions include both idle and absolute expiration, ensuring they automatically expire after inactivity or a fixed lifetime. Additionally, CSRF protection is implemented to safeguard all state-changing requests, providing a secure and reliable session management system.

Role-Based Access Control (RBAC)
Roles
Guest: Not authenticated.
User (default after login): Authenticated end-user who owns a profile and content.
Admin: Elevated privileges for moderation and system management.
How it’s enforced:
Role stored in session after Google OAuth (e.g., req.user.role = 'User' | 'Admin').


Security Implementation Overview

Input Validation Techniques
- All profile update fields (`name`, `email`, `bio`) are validated on the server using express-validator.
- Name:
  - Must be between 3 and 50 characters.
  - Must match the regex `^[A-Za-z\s]+$` (letters and spaces only).
- Email:
  - Validated with `.isEmail()` to enforce standard email format.
  - Normalized using `.normalizeEmail()` before processing.
- Bio:
  - Limited to a maximum of 500 characters**.
  - Validated with a strict regex to allow only letters, numbers, spaces, and basic punctuation (no HTML tags or special characters).
- Invalid input returns a `400 Bad Request` with a descriptive error message and is never stored.

Output Encoding Methods
- Before storing, user-provided fields (`name`, `email`, `bio`) are sanitized using:
  - `express-validator` methods such as `.trim()` and `.escape()`.
  - The escape-html library for extra defense-in-depth.
- When sending data back to the client, all values are returned as plain text.
- On the frontend, React renders values inside JSX (e.g., `{user.displayName}`, `{user.bio}`), which are automatically escaped by React’s rendering engine.
- No `dangerouslySetInnerHTML` is used, preventing user input from being interpreted as HTML or JavaScript.

Encryption Techniques Used
- Sensitive profile fields are encrypted at rest using Node’s built-in crypto module:
  - Algorithm: AES-256-GCM (`aes-256-gcm`).
  - A 256-bit key is derived from an environment variable (`ENCRYPTION_SECRET`) using SHA-256.
  - Encrypted payloads include IV + auth tag + ciphertext, encoded as Base64 for storage.
- The following fields are encrypted before being stored in the in-memory user store:
  - `email`
  - `bio`
- Decryption occurs only when the authenticated user requests their profile (`/auth/me`, `/profile/me`).
- All communication between client and server is protected by **HTTPS**:
  - The backend runs on `https://localhost:3001` with a TLS certificate.
  - Session cookies are configured with `secure: true`, `httpOnly: true`, and `sameSite: 'none'` to protect them from network eavesdropping and client-side access.

Third-Party Libraries & Dependency Management
- Dependencies are managed via npm with `package.json` / `package-lock.json` for both frontend and backend.
- Key security-related libraries:
  - helmet – sets security-related HTTP headers (CSP, HSTS, X-Frame-Options, etc.).
  - express-session – secure session management with HTTP-only, secure cookies.
  - csurf – CSRF protection for state-changing requests.
  - passport & passport-google-oauth20 – secure authentication with Google OAuth 2.0.
  - express-validator – input validation and basic sanitization.
  - escape-html – escaping user input before storage/output.
- Dependencies are periodically reviewed and updated using:
  - `npm audit` to detect known vulnerabilities.
  - Manual updates of npm packages when security advisories or important releases are announced.
