import express from "express";
import cors from "cors";
import cookieParser from "cookie-parser";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import nodemailer from "nodemailer";
import { v4 as uuidv4 } from "uuid";
import mysql from "mysql2";
import "dotenv/config";


//hello

const app = express();

app.use(
  cors({
    origin: "http://localhost:5173",
    credentials: true,
    methods: ["GET", "POST", "PUT", "DELETE"],
  })
);

app.use(express.json());
app.use(cookieParser());

const db = mysql.createConnection({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
});
db.connect((err) => {
  if (err) console.log("DB Connec on Error: ", err);
  else console.log("MySQL Connected");
});

// Generate Referral Code
const generateReferralCode = () => uuidv4().slice(0, 8).toUpperCase();

// Generate JWT Token
const generateToken = (user, expiresIn) => {
  return jwt.sign(
    { id: user.user_id, role: user.role, name: user.name, email: user.email },
    process.env.JWT_SECRET,
    {
      expiresIn,
    }
  );
};

// Nodemailer Setup
const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: process.env.MAIL_USER,
    pass: process.env.MAIL_PASS,
  },
});


// ✅ Middleware for Authentication
const authenticate = async (req, res, next) => {
  const token = req.cookies.auth_token;

  if (!token)
    return res
      .status(401)
      .json({ message: "Access Denied. No Token Provided" });

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);

    // console.log("decoded", decoded);

    // ✅ Fetch Full User Details (Including referral_code) from DB
    const [users] = await db
      .promise()
      .query(
        `SELECT id, name, email, role, referral_code FROM users WHERE email = ?`,
        [decoded.email]
      );

    // console.log("decoded email", decoded.email);
    // console.log("users", users);

    if (users.length === 0) {
      return res.status(404).json({ message: "User not found" });
    }

    req.user = users[0];
    next();
  } catch (err) {
    res.status(401).json({ message: "Invalid Token" });
  }
};

//signup

app.post("/signup", async (req, res) => {
  const { name, email, password, role, referral_code } = req.body;
  // console.log("signup", name, email, password, role, referral_code);

  try {
    // Hash Password
    const hashedPassword = await bcrypt.hash(password, 10);

    let referredBy = null;
    let newReferralCode = null;

    if (role === "reseller") {
      // Generate Referral Code for Reseller
      newReferralCode = generateReferralCode();
    } else if (role === "user" && referral_code) {
      // Validate Referral Code if Provided
      const [referrer] = await db
        .promise()
        .query(`SELECT referral_code FROM users WHERE referral_code = ?`, [
          referral_code,
        ]);

      if (referrer.length === 0)
        return res.status(400).json({ message: "Invalid referral code" });

      referredBy = referral_code;
    }

    // Insert User into Database
    const [result] = await db
      .promise()
      .query(
        `INSERT INTO users (name, email, password, role, referral_code, referred_by) VALUES (?, ?, ?, ?, ?, ?)`,
        [name, email, hashedPassword, role, newReferralCode, referredBy]
      );

    res.json({
      message: "User registered successfully",

      referral_code: newReferralCode,
    });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// *2️⃣ Login API*
app.post("/login", (req, res) => {
  const { email, password, rememberMe } = req.body;
  // console.log(" login ", email, password, rememberMe);

  db.promise()
    .query(`SELECT * FROM users WHERE email = ?`, [email])
    .then(async ([rows]) => {
      if (rows.length === 0)
        return res.status(400).json({ message: "Invalid Email" });

      const user = rows[0];
      const validPass = await bcrypt.compare(password, user.password);
      if (!validPass)
        return res.status(400).json({ message: "Invalid Password" });
      // console.log("1");
      // Set token expiration based on "Remember Me"
      const expiresIn = rememberMe ? "30d" : "1d"; // 30 days if checked, else 1 day
      // console.log("3");

      // Store token in HTTP-only cookie
      const cookieOptions = {
        httpOnly: true, // Prevents XSS attacks
        secure: process.env.NODE_ENV === "production", // Set secure to true in production
      };

      const token = generateToken(user, expiresIn);
      // console.log("4");
      if (rememberMe) {
        // Store token for persistent login (30 days)
        res.cookie("auth_token", token, {
          ...cookieOptions,
          maxAge: 30 * 24 * 60 * 60 * 1000, // 30 days
        });
      } else {
        // Store token for session-based login (expires when the browser is closed)
        res.cookie("auth_token", token, {
          ...cookieOptions,
          maxAge: 1 * 24 * 60 * 60 * 1000, // 1 day
        });
      }
      // console.log("5");
      const userData = {
        user_id: user.id,
        email: user.email,
      };

      // Generate JWT Token
      // console.log("7");
      return res.json({
        message: "Login Successful",
        token,
        userData,
      });
    })
    .catch((err) => res.status(500).json({ message: err.message }));
});

// **3 Forgot Password API (Send OTP)**

app.post("/forgot-password", async (req, res) => {
  const { email } = req.body;
  const otp = Math.floor(100000 + Math.random() * 900000).toString();
  const expiresAt = new Date(Date.now() + 10 * 60000); // 10 min validity

  try {
    // Check if user exists
    const [user] = await db
      .promise()
      .query(`SELECT id FROM users WHERE email = ?`, [email]);
    if (user.length === 0)
      return res.status(400).json({ message: "Email not found" });

    // Remove existing OTPs before inserting new one
    await db
      .promise()
      .query(`DELETE FROM password_resets WHERE email = ?`, [email]);

    // Insert new OTP
    await db
      .promise()
      .query(
        `INSERT INTO password_resets (email, otp, expires_at) VALUES (?, ?, ?)`,
        [email, otp, expiresAt]
      );

    // Email details
    const mailOptions = {
      from: process.env.MAIL_USER,
      to: email,
      subject: "Password Reset OTP",
      text: `Your OTP for password reset is: ${otp}`,
    };

    // Send email
    transporter.sendMail(mailOptions, (error, info) => {
      if (error) {
        console.error("Email Error: ", error);
        return res
          .status(500)
          .json({ message: "Failed to send OTP email", error: error.message });
      }
    });

    // ✅ Send success response outside transporter callback
    return res.status(200).json({ message: "OTP Sent to Email" });
  } catch (err) {
    console.error("Server Error: ", err);
    return res.status(500).json({ message: err.message });
  }
});

// **4 Reset Password API**
app.post("/reset-password", async (req, res) => {
  const { email, otp, newPassword } = req.body;

  const [rows] = await db.promise().query(
    `SELECT * FROM password_resets WHERE email 
    = ? AND otp = ? AND expires_at > NOW()`,
    [email, otp]
  );

  if (rows.length === 0)
    return res.status(400).json({ message: "Invalid or expired OTP" });

  const hashedPassword = await bcrypt.hash(newPassword, 10);
  await db
    .promise()
    .query(`UPDATE users SET password = ? WHERE email = ?`, [
      hashedPassword,
      email,
    ]);

  res.json({ message: "Password Reset Successfull" });
});

// **5 Get Profile API**
app.get("/profile", authenticate, async (req, res) => {
  const [user] = await db.promise().query(
    `SELECT name, email, role, referral_code FROM 
    users WHERE id = ?`,
    [req.user.id]
  );

  if (user.length === 0)
    return res.status(404).json({ message: "User not found" });

  res.json(user[0]);
});

// **6 Super Admin Creates Reseller**
app.post("/add-reseller", authenticate, async (req, res) => {
  if (req.user.role !== "super_admin")
    return res.status(403).json({ message: "Permission  Denied" });

  const { name, email, password } = req.body;
  const hashedPassword = await bcrypt.hash(password, 10);
  const referralCode = generateReferralCode();

  await db.promise().query(
    `INSERT INTO users (name, email, password, role, 
    referral_code) VALUES (?, ?, ?, 'reseller', ?)`,
    [name, email, hashedPassword, referralCode]
  );

  res.json({ message: "Reseller Created", referral_code: referralCode });
});

app.post("/check-used-password", async (req, res) => {
  const { email, newPassword } = req.body;
  // console.log("check ", email, newPassword);

  try {
    const [oldPasswords] = await db
      .promise()
      .query("SELECT password_hash FROM used_passwords WHERE email = ?", [
        email,
      ]);

    for (const record of oldPasswords) {
      const match = await bcrypt.compare(newPassword, record.password_hash);
      if (match) {
        // console.log("Password has been used before");

        return res.status(400).json({
          message:
            "This password has been used before. Please choose a different one.",
        });
      }
    }

    res.status(200).json({ message: "This password is safe to use." });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

// Middleware for Authentication

// *⿣ Protected Route Example (Requires Authentication)*
app.get("/protected-route", authenticate, (req, res) => {
  res.json({ message: "Welcome! You are authenticated.", user: req.user });
});

app.post("/logout", (req, res) => {
  res.clearCookie("auth_token");
  res.json({ message: "Logged out successfully" });
});

// get users
app.get("/users", authenticate, async (req, res) => {
  try {
    let query;
    let params = [];

    // console.log("re", req.userData);

    if (req.user.role === "super_admin") {
      // Super Admin fetches all users and resellers
      query = `SELECT id, name, email, role FROM users WHERE role IN ('user', 'reseller')`;
    } else if (req.user.role === "reseller") {
      // Resellers fetch only their assigned users
      query = `SELECT id, name, email, role FROM users WHERE referred_by = ?`;
      params = [req.user.referral_code]; // Assuming referral_code is assigned to users under a reseller
    } else {
      return res.status(403).json({ message: "Permission Denied" });
    }

    // console.log("qq", query);
    // console.log("zz", req.userData.referral_code);

    const [users] = await db.promise().query(query, params);
    res.json(users);
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

// ✅ API to Edit User, Reseller, or Self Profile
app.put("/users/:id", authenticate, async (req, res) => {
  const { id } = req.params;
  const { name, role } = req.body; // ❌ Email is not editable

  try {
    let query;
    let params = [];

    if (req.user.role === "super_admin") {
      // Super Admin can update any user or reseller
      query = `UPDATE users SET name = ?, role = ? WHERE id = ?`;
      params = [name, role, id];
    } else if (req.user.role === "reseller") {
      // Resellers can only update their own users
      query = `UPDATE users SET name = ? WHERE id = ? AND referred_by = ?`;
      params = [name, id, req.user.referral_code];
    } else if (req.user.id == id) {
      // Users can only update their own profile (except email)
      query = `UPDATE users SET name = ? WHERE id = ?`;
      params = [name, id];
    } else {
      return res.status(403).json({ message: "Permission Denied" });
    }

    const [result] = await db.promise().query(query, params);

    if (result.affectedRows === 0) {
      return res
        .status(404)
        .json({ message: "User not found or unauthorized to edit" });
    }

    res.json({ message: "Profile updated successfully" });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

app.listen(3000, () => console.log("Server running on port 3000"));
