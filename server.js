const express = require("express");
const fs = require("fs");
const bodyParser = require("body-parser");
const cors = require("cors");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const path = require("path");

const app = express();
app.use(cors());
app.use(bodyParser.json());

const SECRET = process.env.SECRET || "super-secret-key";
const PORT = process.env.PORT || 3000;

const USERS_FILE = path.join(__dirname, "users.json");
const MANIFEST_FILE = path.join(__dirname, "manifest.json");
const FILES_FOLDER = path.join(__dirname, "files");

// Load users.json or initialize empty
let users = fs.existsSync(USERS_FILE)
  ? JSON.parse(fs.readFileSync(USERS_FILE, "utf-8"))
  : {};

// Save users.json
function saveUsers() {
  fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2));
}

// ---------------- AUTH -----------------

// Signup
app.post("/api/signup", async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ success: false, msg: "Missing fields" });
  if (users[username]) return res.status(400).json({ success: false, msg: "User exists" });

  const hash = await bcrypt.hash(password, 12);
  users[username] = { password: hash, createdAt: new Date() };
  saveUsers();

  return res.json({ success: true, msg: "Account created" });
});

// Login
app.post("/api/login", async (req, res) => {
  const { username, password } = req.body;
  if (!users[username]) return res.status(400).json({ success: false, msg: "Invalid user" });

  const match = await bcrypt.compare(password, users[username].password);
  if (!match) return res.status(400).json({ success: false, msg: "Wrong password" });

  const token = jwt.sign({ username }, SECRET, { expiresIn: "30d" });
  return res.json({ success: true, token });
});

// Optional: verify token middleware
function authMiddleware(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth) return res.status(401).json({ msg: "No token" });
  const token = auth.split(" ")[1];
  try {
    req.user = jwt.verify(token, SECRET);
    next();
  } catch (err) {
    return res.status(401).json({ msg: "Invalid token" });
  }
}

// ---------------- MANIFEST -----------------
app.get("/api/manifest", (req, res) => {
  if (!fs.existsSync(MANIFEST_FILE)) return res.status(404).json({ msg: "Manifest not found" });
  const manifest = JSON.parse(fs.readFileSync(MANIFEST_FILE, "utf-8"));
  res.json(manifest);
});

// Serve files
app.use("/files", express.static(FILES_FOLDER));

// ---------------- START SERVER -----------------
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
