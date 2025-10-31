import React, { useState } from "react";

function Contact({ csrfToken }) {
  const [form, setForm] = useState({ name: "", email: "", message: "" });
  const [response, setResponse] = useState(null);
  const [error, setError] = useState(null);

  const handleChange = (e) => {
    setForm({ ...form, [e.target.name]: e.target.value });
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError(null);
    setResponse(null);

    try {
      const res = await fetch("https://localhost:3001/contact", {
        method: "POST",
        credentials: "include",
        headers: {
          "Content-Type": "application/json",
          "x-csrf-token": csrfToken, // ✅ send CSRF token header
        },
        body: JSON.stringify(form),
      });

      const data = await res.json();
      if (res.ok) {
        setResponse(data.message);
        setForm({ name: "", email: "", message: "" });
      } else {
        setError(data.error || "Something went wrong.");
      }
    } catch (err) {
      setError("Network error. Please try again.");
    }
  };

  return (
    <div style={{ marginTop: "2rem" }}>
      <h2>Contact Me</h2>
      <form onSubmit={handleSubmit}>
        <input
          name="name"
          placeholder="Your Name"
          value={form.name}
          onChange={handleChange}
          required
        />
        <br />
        <input
          name="email"
          type="email"
          placeholder="Your Email"
          value={form.email}
          onChange={handleChange}
          required
        />
        <br />
        <textarea
          name="message"
          placeholder="Your Message"
          rows="4"
          value={form.message}
          onChange={handleChange}
          required
        />
        <br />
        <button type="submit">Send</button>
      </form>

      {response && <p style={{ color: "green" }}>{response}</p>}
      {error && <p style={{ color: "red" }}>{error}</p>}
    </div>
  );
}

export default Contact;
