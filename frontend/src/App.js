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

  // --- Data from backend ---
  const [posts, setPosts] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  // On load, check session (Google SSO) and load posts
  const [csrfToken, setCsrfToken] = useState('');

useEffect(() => {
  fetch('https://localhost:3001/csrf-token', { credentials: 'include' })
    .then(r => r.json())
    .then(d => setCsrfToken(d.csrfToken))
    .catch(() => {});

    fetch('https://localhost:3001/auth/me', { credentials: 'include' })
    .then(r => (r.status === 200 ? r.json() : { user: null }))
    .then(({ user }) => {
      if (user) {
        setUser(user);
        setIsLoggedIn(true);
      }
    })
    .catch(() => {});
}, []);

const sendContact = async () => {
  const res = await fetch('https://localhost:3001/contact', {
    method: 'POST',
    credentials: 'include',
    headers: {
      'Content-Type': 'application/json',
      'x-csrf-token': csrfToken, // send it here
    },
    body: JSON.stringify({ message: 'Test message' }),
  });
  const data = await res.json();
  console.log(data);
};

  // --- Fake Login Handler ---
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

  // --- Logout (Google session) ---
  const handleLogout = async () => {
    try {
      await fetch("https://localhost:3001/auth/logout", { method: "POST", credentials: "include" });

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

  return (
    <div style={{ margin: "20px", fontFamily: "Arial" }}>
      <h1>Developer Portfolio</h1>


      {!isLoggedIn ? (
        <>
          {/* Google SSO button */}
          <button onClick={googleLogin} style={{ marginBottom: 16 }}>
            Sign in with Google
          </button>

         
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
          <p>
            Welcome, {user?.displayName || user?.name}
            {user?.email ? ` (${user.email})` : ""}
          </p>
          {user?.photo && (
            <img
              src={user.photo}
              alt="avatar"
              width={48}
              height={48}
              style={{ borderRadius: "50%" }}
            />
          )}
          <button onClick={handleLogout}>Logout</button>

          <Profile profile={profile} />
          <Projects projects={projects} />
          <Blog blogs={blogs} />
          <Contact csrfToken={csrfToken} />
        </>
      )}
    </div>
  );
}

export default App;
