const express = require("express");
const { register, login, verifyEmail, getProfile } = require("../controllers/authController");
const { authMiddleware } = require("../middleware/authMiddleware");

const router = express.Router();

// Register user
router.post("/signup", register);

// Login user
router.post("/login", login);

// Email verification
router.get("/verify-email", verifyEmail);

// Protected profile route
router.get("/profile", authMiddleware, getProfile);

module.exports = router;
