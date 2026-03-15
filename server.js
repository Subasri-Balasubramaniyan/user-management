const express = require("express");
const fs = require("fs");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

const app = express();
app.use(express.json());

const SECRET_KEY = "mysecretkey";
const PORT = 3000;

/* ---------------- FILE SYSTEM FUNCTIONS ---------------- */

const getUsers = () => {
  const data = fs.readFileSync("users.json");
  return JSON.parse(data);
};

const saveUsers = (users) => {
  fs.writeFileSync("users.json", JSON.stringify(users, null, 2));
};

/* ---------------- REGISTER ---------------- */

app.post("/register", async (req, res) => {
  try {
    const { username, password, role } = req.body;

    let users = getUsers();

    const userExists = users.find(u => u.username === username);
    if (userExists) {
      return res.status(400).json({ message: "User already exists" });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const newUser = {
      id: Date.now(),
      username,
      password: hashedPassword,
      role: role || "user"
    };

    users.push(newUser);
    saveUsers(users);

    res.status(201).json({ message: "User registered successfully" });

  } catch (error) {
    res.status(500).json({ message: "Error registering user" });
  }
});

/* ---------------- LOGIN ---------------- */

app.post("/login", async (req, res) => {
  try {
    const { username, password } = req.body;

    const users = getUsers();
    const user = users.find(u => u.username === username);

    if (!user) {
      return res.status(400).json({ message: "Invalid credentials" });
    }

    const isMatch = await bcrypt.compare(password, user.password);

    if (!isMatch) {
      return res.status(400).json({ message: "Invalid credentials" });
    }

    const token = jwt.sign(
      { id: user.id, role: user.role },
      SECRET_KEY,
      { expiresIn: "1h" }
    );

    res.json({ message: "Login successful", token });

  } catch (error) {
    res.status(500).json({ message: "Error logging in" });
  }
});

/* ---------------- AUTH MIDDLEWARE ---------------- */

const verifyToken = (req, res, next) => {
  const header = req.headers.authorization;

  if (!header) {
    return res.status(401).json({ message: "Access Denied" });
  }

  const token = header.split(" ")[1];

  jwt.verify(token, SECRET_KEY, (err, decoded) => {
    if (err) {
      return res.status(403).json({ message: "Invalid Token" });
    }

    req.user = decoded;
    next();
  });
};

/* ---------------- ROLE MIDDLEWARE ---------------- */

const checkAdmin = (req, res, next) => {
  if (req.user.role !== "admin") {
    return res.status(403).json({ message: "Admin access required" });
  }
  next();
};

/* ---------------- PROTECTED ROUTES ---------------- */

app.get("/profile", verifyToken, (req, res) => {
  res.json({ message: "Welcome User", user: req.user });
});

app.get("/users", verifyToken, checkAdmin, (req, res) => {
  const users = getUsers();
  res.json(users);
});

/* ---------------- ERROR HANDLER ---------------- */

app.use((err, req, res, next) => {
  res.status(500).json({ message: "Something went wrong" });
});

/* ---------------- SERVER ---------------- */

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});