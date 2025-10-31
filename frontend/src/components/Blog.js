import React from "react";

function Blog({ blogs }) {
  return (
    <section>
      <h2>Blog</h2>
      {blogs.map((post, index) => (
        <div key={index} style={{ marginBottom: "10px" }}>
          <h3>{post.title}</h3>
          <p>{post.content}</p>
        </div>
      ))}
    </section>
  );
}

export default Blog;
