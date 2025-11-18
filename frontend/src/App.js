import React, { useEffect, useState } from "react";
import Profile from "./components/Profile";
import Projects from "./components/Projects";
import Blog from "./components/Blog";
import Contact from "./components/Contact";

function App() {
  // --- Auth / user state ---
  const [isLoggedIn, setIsLoggedIn] = useState(false);
  const [user, setUser] = useState(null);
  const [loginData, setLoginData] = useState({ username: "", password: "" });

  // --- Data from backend / CSRF ---
  const [csrfToken, setCsrfToken] = useState("");
  const [loadingUser, setLoadingUser] = useState(true);
  const [error, setError] = useState("");

  useEffect(() => {
  // 1) CSRF
  fetch("https://localhost:3001/csrf-token", { credentials: "include" })
    .then((r) => r.json())
    .then((d) => setCsrfToken(d.csrfToken))
    .catch(() => {});

  // 2) Auth/session
  fetch("https://localhost:3001/auth/me", { credentials: "include" })
    .then((r) => (r.status === 200 ? r.json() : { user: null }))
    .then(async ({ user }) => {
      if (user) {
        setUser(user);
        setIsLoggedIn(true);

        // Fetch current profile to pre-fill form
        try {
          const res = await fetch("https://localhost:3001/profile/me", {
            credentials: "include",
          });
          if (res.ok) {
            const data = await res.json();
            setProfileForm({
              name: data.profile.name || "",
              email: data.profile.email || "",
              bio: data.profile.bio || "",
            });
          }
        } catch (e) {
          console.error("Failed to load profile", e);
        }
      }
      setLoadingUser(false);
    })
    .catch(() => {
      setError("Could not verify session.");
      setLoadingUser(false);
    });
}, []);


  // Example: contact POST using CSRF
  const sendContact = async () => {
    const res = await fetch("https://localhost:3001/contact", {
      method: "POST",
      credentials: "include",
      headers: {
        "Content-Type": "application/json",
        "x-csrf-token": csrfToken,
      },
      body: JSON.stringify({ message: "Test message" }),
    });
    const data = await res.json();
    console.log(data);
  };

  // --- Fake Login Handler (demo only) ---
  // For the secure, real flow you rely on Google login.
  const handleLogin = (e) => {
    e.preventDefault();
    if (loginData.username && loginData.password) {
      setIsLoggedIn(true);
      setUser({ name: loginData.username });
      setLoginData({ username: "", password: "" });
    } else {
      alert("Please enter username and password");
    }
  };

  // --- Google SSO: start login flow ---
  const googleLogin = () => {
    window.location.href = "https://localhost:3001/auth/google";
  };

  // --- Logout (Google session) with CSRF ---
  const handleLogout = async () => {
    try {
      await fetch("https://localhost:3001/auth/logout", {
        method: "POST",
        credentials: "include",
        headers: {
          "Content-Type": "application/json",
          "x-csrf-token": csrfToken, // IMPORTANT for CSRF-protected POST
        },
      });

      setIsLoggedIn(false);
      setUser(null);
    } catch (_) {}
  };

  // --- Portfolio States ---
  const [profile, setProfile] = useState({
    name: "Your Name",
    bio: "Short bio about yourself.",
    technologies: ["React", "JavaScript", "HTML", "CSS"],
  });

  const [profileForm, setProfileForm] = useState({
  name: "",
  email: "",
  bio: "",
  });

const [profileMessage, setProfileMessage] = useState("");


  const [projects, setProjects] = useState([
    {
      title: "Portfolio Website",
      description: "A personal portfolio built with React.",
      link: "https://github.com/yourusername/portfolio",
    },
  ]);

  const [blogs, setBlogs] = useState([
    {
      title: "Getting Started with React",
      content: "React is a great library for building UIs...",
    },
  ]);

  const handleProfileSubmit = async (e) => {
  e.preventDefault();
  setProfileMessage("");

  try {
    const res = await fetch("https://localhost:3001/profile", {
      method: "POST",
      credentials: "include",
      headers: {
        "Content-Type": "application/json",
        "x-csrf-token": csrfToken,
      },
      body: JSON.stringify(profileForm),
    });

    const data = await res.json();

    if (!res.ok) {
      // show first validation error, if any
      if (data.errors && data.errors.length > 0) {
        setProfileMessage(data.errors[0].msg);
      } else {
        setProfileMessage("Profile update failed.");
      }
    } else {
      setProfileMessage("Profile updated successfully.");
      // update displayed user name/email too
      setUser((prev) =>
        prev
          ? {
              ...prev,
              displayName: data.profile.name,
              email: data.profile.email,
              bio: data.profile.bio,
            }
          : prev
      );
    }
  } catch (err) {
    console.error(err);
    setProfileMessage("Network error updating profile.");
  }
};


  if (loadingUser) {
    return <p style={{ margin: "20px", fontFamily: "Arial" }}>Loading...</p>;
  }

  return (
    <div style={{ margin: "20px", fontFamily: "Arial" }}>
      <h1>Developer Portfolio</h1>

      {!isLoggedIn ? (
        <>
          {/* Google SSO button */}
          <button onClick={googleLogin} style={{ marginBottom: 16 }}>
            Sign in with Google
          </button>

          {/* Demo-only login form */}
          <form onSubmit={handleLogin}>
            <h2>Login (demo)</h2>
            <input
              type="text"
              placeholder="Username"
              value={loginData.username}
              onChange={(e) =>
                setLoginData({ ...loginData, username: e.target.value })
              }
              required
            />
            <br />
            <input
              type="password"
              placeholder="Password"
              value={loginData.password}
              onChange={(e) =>
                setLoginData({ ...loginData, password: e.target.value })
              }
              required
            />
            <br />
            <button type="submit">Login</button>
          </form>
        </>
      ) : (
        <>
          {/* PHASE 3: DASHBOARD SECTION */}

          <div
            style={{
              maxWidth: "700px",
              margin: "20px 0",
              background: "#fff",
              borderRadius: "8px",
              padding: "16px",
              boxShadow: "0 2px 8px rgba(0,0,0,0.08)",
            }}
          >
            {/* Welcome message with user’s name */}
            <h2>
              Welcome, {user?.displayName || user?.name}
              {user?.email ? ` (${user.email})` : ""}
            </h2>

            {/* Avatar if available */}
            {user?.photo && (
              <img
                src={user.photo}
                alt="avatar"
                width={64}
                height={64}
                style={{ borderRadius: "50%", marginTop: 8 }}
              />
            )}

            {/* User-specific details */}
            <section
              style={{
                marginTop: 16,
                padding: 12,
                background: "#fafafa",
                borderRadius: 6,
                border: "1px solid #e0e0e0",
              }}
            >
              <h3>Your Details</h3>
              <p>
                <strong>Name:</strong> {user?.displayName || user?.name}
              </p>
              {user?.email && (
                <p>
                  <strong>Email:</strong> {user.email}
                </p>
              )}
            </section>

            {/* Profile update form (Part B) */}
<section
  style={{
    marginTop: 16,
    padding: 12,
    borderRadius: 6,
    border: "1px solid #e0e0e0",
    background: "#fcfcfc",
  }}
>
  <h3>Update Profile</h3>
  <form onSubmit={handleProfileSubmit}>
    <div style={{ marginBottom: 8 }}>
      <label>
        Name (3–50 letters):
        <br />
        <input
          type="text"
          value={profileForm.name}
          onChange={(e) =>
            setProfileForm({ ...profileForm, name: e.target.value })
          }
          required
        />
      </label>
    </div>

    <div style={{ marginBottom: 8 }}>
      <label>
        Email:
        <br />
        <input
          type="email"
          value={profileForm.email}
          onChange={(e) =>
            setProfileForm({ ...profileForm, email: e.target.value })
          }
          required
        />
      </label>
    </div>

    <div style={{ marginBottom: 8 }}>
      <label>
        Bio (max 500 chars, no HTML or special characters):
        <br />
        <textarea
          value={profileForm.bio}
          onChange={(e) =>
            setProfileForm({ ...profileForm, bio: e.target.value })
          }
          maxLength={500}
          rows={4}
        />
      </label>
    </div>

    <button type="submit">Save Profile</button>
  </form>

  {profileMessage && (
    <p style={{ marginTop: 8 }}>
      <strong>{profileMessage}</strong>
    </p>
  )}
</section>


            {/* Logout button */}
            <button
              onClick={handleLogout}
              style={{
                marginTop: 16,
                padding: "8px 16px",
                borderRadius: 4,
                border: "none",
                cursor: "pointer",
                background: "#e53935",
                color: "#fff",
              }}
            >
              Logout
            </button>
          </div>

          {/* Existing portfolio sections */}
          <Profile user={user} technologies={profile.technologies} />
          <Projects projects={projects} />
          <Blog blogs={blogs} />
          <Contact csrfToken={csrfToken} />
        </>
      )}
    </div>
  );
}

export default App;
