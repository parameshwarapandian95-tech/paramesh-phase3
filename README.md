// app.js
const express = require("express");
const jwt = require("jsonwebtoken");
const dotenv = require("dotenv");
const app = express();

// Load environment variables
dotenv.config();

// Mock user data
const user = { id: 1, username: "john_doe" };

// Secret key for JWT
const accessTokenSecret = process.env.ACCESS_TOKEN_SECRET;
const refreshTokenSecret = process.env.REFRESH_TOKEN_SECRET;

// Store refresh tokens (in a real app, use a database)
let refreshTokens = [];

// Middleware to verify access token
function authenticateToken(req, res, next) {
  const token = req.headers["authorization"];
  if (token == null) return res.sendStatus(401);

  jwt.verify(token, accessTokenSecret, (err, user) => {
    if (err) return res.sendStatus(403); // Token expired or invalid
    req.user = user;
    next();
  });
}

// Endpoint to login and get access & refresh tokens
app.post("/login", (req, res) => {
  // Normally you'd authenticate the user here, for now, we'll assume success.
  
  const accessToken = jwt.sign(user, accessTokenSecret, { expiresIn: "15m" });
  const refreshToken = jwt.sign(user, refreshTokenSecret);
  
  // Store refresh token
  refreshTokens.push(refreshToken);
  
  res.json({
    accessToken,
    refreshToken,
  });
});

// Endpoint to refresh the access token using refresh token
app.post("/token", (req, res) => {
  const refreshToken = req.body.refreshToken;
  if (refreshToken == null) return res.sendStatus(401);
  
  if (!refreshTokens.includes(refreshToken)) return res.sendStatus(403);
  
  jwt.verify(refreshToken, refreshTokenSecret, (err, user) => {
    if (err) return res.sendStatus(403);
    
    const accessToken = jwt.sign({ id: user.id, username: user.username }, accessTokenSecret, { expiresIn: "15m" });
    res.json({ accessToken });
  });
});

// Protected route, only accessible with a valid access token
app.get("/protected", authenticateToken, (req, res) => {
  res.send("This is a protected route");
});

// Start server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
