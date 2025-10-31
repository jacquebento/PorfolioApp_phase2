import React from "react";

function Profile({ profile }) {
  return (
    <section>
      <h2>Profile</h2>
      <p><strong>Name:</strong> {profile.name}</p>
      <p><strong>Bio:</strong> {profile.bio}</p>
      <p><strong>Technologies:</strong> {profile.technologies.join(", ")}</p>
    </section>
  );
}

export default Profile;
