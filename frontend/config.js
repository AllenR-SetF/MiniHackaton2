// Frontend configuration. The API lives on a DIFFERENT origin than these pages.
// After deploying the backend, put its HTTPS URL (including /prjM3) below.
window.APP_CONFIG = {
  TEAM: 'prjM3',
  API_BASE: ['localhost', '127.0.0.1'].includes(location.hostname)
    ? 'http://localhost:3000/prjM3'
    : 'https://prjm3-minihackaton2-production.up.railway.app/prjM3',
};
