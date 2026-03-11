import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import App from "./App";

const style = document.createElement("style");
style.textContent = `
  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
  html, body, #root { margin: 0; padding: 0; background: #0f1117; min-height: 100vh; }
  select option { background: #1a1d2e; color: #e2e8f0; }
`;
document.head.appendChild(style);

createRoot(document.getElementById("root")).render( <StrictMode> <App /> </StrictMode> );

