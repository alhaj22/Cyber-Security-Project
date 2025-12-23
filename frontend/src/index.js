import React from "react";
import ReactDOM from "react-dom/client";
import { BrowserRouter } from "react-router-dom";
import App from "./App";

/* ✅ CSS imports yahan */
import "./styles/base.css";
import "./styles/navbar.css";
import "./styles/hero.css";
import "./styles/pages.css";
import "./styles/scan.css";
import "./styles/footer.css";

const root = ReactDOM.createRoot(document.getElementById("root"));

root.render(
  <BrowserRouter>
    <App />
  </BrowserRouter>
);
