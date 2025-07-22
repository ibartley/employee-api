const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const { expressjwt: jwt } = require('express-jwt');
const jwksRsa = require('jwks-rsa');

const app = express();
app.use(cors());
app.use(bodyParser.json());

// In-memory employee data
let employees = [];

// *** CONFIGURATION - REPLACE WITH YOUR VALUES ***
const TENANT_B_ID = "9cce0e15-6053-428f-ba65-62f30ae53bd6"; //  "9cce0e15-6053-428f-ba65-62f30ae53bd6"
const API_APP_ID = "935cc781-69d7-440f-aa23-114a6ab3007c"; // 935cc781-69d7-440f-aa23-114a6ab3007c  (App Registration Application ID in tenant B)
const SCOPES = {
  read: `api://${API_APP_ID}/Employee.Read.All`,
  write: `api://${API_APP_ID}/Employee.Write.All`
};
const EMAIL_CLAIM = "email";

// JWT validation middleware, using Tenant B as the issuer
const checkJwt = jwt({
  secret: jwksRsa.expressJwtSecret({
    cache: true,
    rateLimit: true,
    jwksRequestsPerMinute: 5,
    jwksUri: `https://login.microsoftonline.com/${TENANT_B_ID}/discovery/v2.0/keys`
  }),
  audience: API_APP_ID, // Must match the "aud" in the access token, your API AppId
  issuer: `https://sts.windows.net/${TENANT_B_ID}/`,
  algorithms: ['RS256'],
});

// Scope check
function requireScope(requiredScope) {
  return function(req, res, next) {
    const { scp } = req.auth;
    if (!scp || !scp.split(" ").includes(requiredScope.split('/').pop()))
      return res.status(403).json({ error: "Insufficient scope" });
    next();
  }
}

// Email claim check
function requireEmail(req, res, next) {
  const email = req.auth[EMAIL_CLAIM];
  if (!email) return res.status(400).json({ error: "No email claim present" });
  req.userEmail = email;
  next();
}

// Routes
app.get('/employees', checkJwt, requireScope("Employee.Read.All"), requireEmail, (req, res) => {
  res.json(employees);
});

app.post('/employees', checkJwt, requireScope("Employee.Write.All"), requireEmail, (req, res) => {
  const { employeeName, employeeId } = req.body;
  if (!employeeName || !employeeId) {
    return res.status(400).json({ error: 'Missing employeeName or employeeId' });
  }
  if (employees.some(emp => emp.employeeId === employeeId)) {
    return res.status(409).json({ error: 'Employee ID already exists' });
  }
  const newEmployee = { employeeName, employeeId, createdBy: req.userEmail };
  employees.push(newEmployee);
  res.status(201).json(newEmployee);
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Employee API running on port ${PORT}`);
});
