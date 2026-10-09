// Frontend runtime config. Safe to be public - it must NEVER contain secrets.
// Empty API_URL = same-origin (relative /api calls). When served by server.js this file is
// generated dynamically from PUBLIC_API_URL. For a separate static host (Netlify etc.) it is
// written at build time by:  node scripts/write-config.js   (reads the API_URL env var).
window.APP_CONFIG = { API_URL: "" };
