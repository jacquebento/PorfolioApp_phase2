import React from "react";

function Profile({ user, technologies }) {
  // Fallbacks in case something is missing
  const name = user?.displayName || user?.name || "Your Name";
  const bio =
    user?.bio || "Short bio about yourself. Update your profile to customize this.";

  return (
    <section>
      <h2>Profile</h2>
      <p>
        <strong>Name:</strong> {name}
      </p>
      <p>
        <strong>Bio:</strong> {bio}
      </p>
      <p>
        <strong>Technologies:</strong> {technologies.join(", ")}
      </p>
    </section>
  );
}

export default Profile;

