const User = require("../models/User");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const nodemailer = require("nodemailer");

const generateToken = (userId) => {
  return jwt.sign({ userId }, process.env.JWT_SECRET, { expiresIn: "1h" });
};

// Email verification token generation
const generateVerificationToken = (userId) => {
  return jwt.sign({ userId }, process.env.JWT_SECRET, { expiresIn: "1d" });
};

// Email transporter configuration (for email verification)
const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASSWORD,
  },
});

// @desc   Register new user
// @route  POST /api/signup
exports.register = async (req, res) => {
  const { firstName, lastName, email, password, role, companyDetails } = req.body;

  try {
    const userExists = await User.findOne({ email });
    if (userExists) {
      return res.status(400).json({ message: "User already exists" });
    }

    const user = await User.create({
      firstName,
      lastName,
      email,
      password,
      role,
      companyDetails: role === "company" ? companyDetails : undefined,
    });

    const token = generateVerificationToken(user._id);
    user.verificationToken = token; // Save the token in the user record
    await user.save(); // Save the user with the token

    // Send verification email
    const verificationUrl = `http://localhost:5000/api/verify-email?token=${token}`;
    await transporter.sendMail({
      to: user.email,
      subject: "Email Verification",
      html: `<h1>Verify your email</h1><p>Click the link below to verify your account:</p><a href="${verificationUrl}">Verify</a>`,
    });

    res.status(201).json({ message: "Registration successful. Please check your email to verify your account." });
  } catch (error) {
    res.status(500).json({ message: "Server error", error });
  }
};

// @desc   Email verification
// @route  GET /api/verify-email
exports.verifyEmail = async (req, res) => {
  const token = req.query.token;

  try {
    const user = await User.findOne({ verificationToken: token }); // Find user by verification token

    if (!user) return res.status(400).json({ message: "Invalid or expired token" });
    if (user.isVerified) return res.status(400).json({ message: "User is already verified" });

    user.isVerified = true;
    user.verificationToken = undefined; // Clear the verification token after successful verification
    await user.save();

    res.status(200).json({ message: "Email verified successfully" });
  } catch (error) {
    res.status(400).json({ message: "Invalid or expired token" });
  }
};

// @desc   Login user
// @route  POST /api/login
exports.login = async (req, res) => {
  const { email, password, role } = req.body;

  try {
    const user = await User.findOne({ email });

    if (!user) return res.status(400).json({ message: "Invalid email or password" });
    if (!user.isVerified) return res.status(400).json({ message: "Please verify your email first" });
    if (user.role !== role) return res.status(400).json({ message: "Role mismatch" });

    const isMatch = await user.matchPassword(password);
    if (!isMatch) return res.status(400).json({ message: "Invalid email or password" });

    const token = generateToken(user._id);
    res.status(200).json({ token });
  } catch (error) {
    res.status(500).json({ message: "Server error", error });
  }
};

// @desc   Get user profile (protected)
// @route  GET /api/profile
exports.getProfile = async (req, res) => {
  try {
    const user = await User.findById(req.user);
    if (!user) return res.status(404).json({ message: "User not found" });
    res.status(200).json(user);
  } catch (error) {
    res.status(500).json({ message: "Server error", error });
  }
};
