import React from "react";

function Projects({ projects }) {
  return (
    <section>
      <h2>Projects</h2>
      {projects.map((proj, index) => (
        <div key={index} style={{ marginBottom: "10px" }}>
          <h3>{proj.title}</h3>
          <p>{proj.description}</p>
          <a href={proj.link} target="_blank" rel="noreferrer">View Project</a>
        </div>
      ))}
    </section>
  );
}

export default Projects;
