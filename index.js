require("dotenv").config();

const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const crypto = require("crypto");
const nodemailer = require("nodemailer");
const cors = require("cors");

const app = express();

const PORT = 8000;

const JWT_SECRET = process.env.JWT_SECRET;

// ====================== MIDDLEWARE ======================

app.use(cors({
    origin: "http://127.0.0.1:5500",
    credentials: true
}));

app.use(express.json());

app.use(express.urlencoded({ extended: true }));

// ====================== MONGODB CONNECTION ======================

mongoose.connect("mongodb://127.0.0.1:27017/authapp")
    .then(() => {
        console.log("MongoDB Connected");
    })
    .catch((err) => {
        console.log("MongoDB Connection Error:", err);
    });

// ====================== EMAIL TRANSPORTER ======================

const transporter = nodemailer.createTransport({
    service: "gmail",
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS
    }
});

// ====================== USER SCHEMA ======================

const userSchema = new mongoose.Schema({

    name: {
        type: String,
        required: true
    },

    email: {
        type: String,
        required: true,
        unique: true
    },

    phone: {
        type: String,
        required: true,
        unique: true
    },

    address: {
        type: String
    },

    state: {
        type: String
    },

    city: {
        type: String
    },

    password: {
        type: String,
        required: true
    },

    isVerified: {
        type: Boolean,
        default: false
    },

    verifiedAt: {
        type: Date
    },

    verifyEmailToken: {
        type: String
    },

    verifyEmailExpires: {
        type: Date
    },

    resetPasswordToken: {
        type: String
    },

    resetPasswordExpires: {
        type: Date
    }

}, {
    timestamps: true
});

const User = mongoose.model("User", userSchema);

// ====================== AUTH MIDDLEWARE ======================

const auth = async (req, res, next) => {

    try {

        let token = req.headers.authorization;

        if (!token) {

            return res.status(401).redirect("/login");
        }

        if (token.startsWith("Bearer ")) {

            token = token.split(" ")[1];
        }

        const decoded = jwt.verify(token, JWT_SECRET);

        const user = await User.findById(decoded.id)
            .select("-password");

        if (!user) {

            return res.status(401).redirect("/login");
        }

        req.user = user;

        next();

    } catch (error) {

        return res.status(401).redirect("/login");
    }
};

// ====================== SIGNUP ======================

app.post("/signup", async (req, res) => {

    try {

        const {
            name,
            email,
            phone,
            address,
            state,
            city,
            password
        } = req.body;

        // ====================== REQUIRED FIELD VALIDATION ======================

        const requiredFields = {
            name,
            email,
            phone,
            password
        };

        for (const field in requiredFields) {

            if (!requiredFields[field]) {

                return res.status(400).json({
                    message: `${field} is required`
                });
            }
        }

        // ====================== CHECK EXISTING USER ======================

        const existingUser = await User.findOne({
            $or: [
                { email },
                { phone }
            ]
        });

        if (existingUser) {

            return res.status(400).json({
                message: "User Already Exists"
            });
        }

        // ====================== HASH PASSWORD ======================

        const hashedPassword = await bcrypt.hash(password, 10);

        // ====================== EMAIL VERIFICATION TOKEN ======================

        const verifyToken = crypto.randomBytes(32).toString("hex");

        // ====================== CREATE USER ======================

        const user = await User.create({
            name,
            email,
            phone,
            address,
            state,
            city,
            password: hashedPassword,
            verifyEmailToken: verifyToken,
            verifyEmailExpires: Date.now() + 3600000
        });

        // ====================== VERIFICATION LINK ======================

        const verifyLink =
            `http://localhost:${PORT}/verify-email/${verifyToken}`;

        // ====================== SEND EMAIL ======================

        await transporter.sendMail({
            from: process.env.EMAIL_USER,
            to: email,
            subject: "Verify Your Email",
            html: `
                <h2>Email Verification</h2>

                <p>
                    Click the link below to verify your email:
                </p>

                <a href="${verifyLink}">
                    ${verifyLink}
                </a>
            `
        });

        // ====================== REMOVE SENSITIVE DATA ======================

        const userResponse = user.toObject();

        delete userResponse.password;

        delete userResponse.verifyEmailToken;

        delete userResponse.resetPasswordToken;

        // ====================== RESPONSE ======================

        return res.status(201).json({
            message: "Signup Successful. Verification email sent.",
            user: userResponse
        });

    } catch (error) {

        return res.status(500).json({
            error: error.message
        });
    }
});

// ====================== VERIFY EMAIL ======================

app.get("/verify-email/:token", async (req, res) => {

    try {

        const user = await User.findOne({
            verifyEmailToken: req.params.token,
            verifyEmailExpires: {
                $gt: Date.now()
            }
        });

        if (!user) {

            return res.status(400).json({
                message: "Invalid or Expired Verification Token"
            });
        }

        if (user.isVerified) {

            return res.status(400).json({
                message: "Email already verified"
            });
        }

        user.isVerified = true;

        user.verifiedAt = new Date();

        user.verifyEmailToken = undefined;

        user.verifyEmailExpires = undefined;

        await user.save();

        return res.json({
            message: "Email Verified Successfully"
        });

    } catch (error) {

        return res.status(500).json({
            error: error.message
        });
    }
});

// ====================== LOGIN ======================

app.post("/login", async (req, res) => {

    try {

        const {
            emailOrPhone,
            password
        } = req.body;

        if (!emailOrPhone || !password) {

            return res.status(400).json({
                message: "Email/Phone and Password are required"
            });
        }

        const user = await User.findOne({
            $or: [
                { email: emailOrPhone },
                { phone: emailOrPhone }
            ]
        });

        if (!user) {

            return res.status(401).json({
                message: "Invalid Credentials"
            });
        }

        const isMatch =
            await bcrypt.compare(password, user.password);

        if (!isMatch) {

            return res.status(401).json({
                message: "Invalid Credentials"
            });
        }

        if (!user.isVerified) {

            return res.status(401).json({
                message: "Please verify your email first"
            });
        }

        const token = jwt.sign(
            { id: user._id },
            JWT_SECRET,
            { expiresIn: "7d" }
        );

        return res.json({
            message: "Login Successful",
            token
        });

    } catch (error) {

        return res.status(500).json({
            error: error.message
        });
    }
});

// ====================== USER PROFILE ======================

app.get("/profile", auth, async (req, res) => {

    try {

        return res.json({
            success: true,
            user: req.user
        });

    } catch (error) {

        return res.status(500).json({
            error: error.message
        });
    }
});

// ====================== UPDATE PROFILE ======================

app.put("/update_profile", auth, async (req, res) => {

    try {

        const {
            name,
            phone,
            address,
            state,
            city
        } = req.body;

        const updatedUser = await User.findByIdAndUpdate(
            req.user._id,
            {
                name,
                phone,
                address,
                state,
                city
            },
            {
                returnDocument: "after"
            }
        ).select("-password");

        return res.json({
            message: "Profile Updated",
            updatedUser
        });

    } catch (error) {

        return res.status(500).json({
            error: error.message
        });
    }
});

// ====================== FORGOT PASSWORD ======================

app.post("/forgot-password", async (req, res) => {

    try {

        const { email } = req.body;

        if (!email) {

            return res.status(400).json({
                message: "Email is required"
            });
        }

        const user = await User.findOne({ email });

        if (!user) {

            return res.status(404).json({
                message: "User Not Found"
            });
        }

        // Generate token

        const resetToken =
            crypto.randomBytes(32).toString("hex");

        // Hash token

        const hashedToken = crypto
            .createHash("sha256")
            .update(resetToken)
            .digest("hex");

        // Save token

        user.resetPasswordToken = hashedToken;

        user.resetPasswordExpires =
            Date.now() + 3600000;

        await user.save();

        // Reset link

        const resetLink =
            `http://localhost:${PORT}/reset-password/${resetToken}`;

        // Send email

        await transporter.sendMail({
            from: process.env.EMAIL_USER,
            to: email,
            subject: "Reset Password",
            html: `
                <h2>Reset Password</h2>

                <p>
                    Click the link below to reset your password:
                </p>

                <a href="${resetLink}">
                    ${resetLink}
                </a>
            `
        });

        return res.json({
            message: "Password reset link sent to email"
        });

    } catch (error) {

        return res.status(500).json({
            error: error.message
        });
    }
});

// ====================== RESET PASSWORD ======================

app.post("/reset-password/:token", async (req, res) => {

    try {

        const { newPassword } = req.body;

        if (!newPassword) {

            return res.status(400).json({
                message: "New Password is required"
            });
        }

        // Hash token

        const hashedToken = crypto
            .createHash("sha256")
            .update(req.params.token)
            .digest("hex");

        // Find user

        const user = await User.findOne({
            resetPasswordToken: hashedToken,
            resetPasswordExpires: {
                $gt: Date.now()
            }
        });

        if (!user) {

            return res.status(400).json({
                message: "Invalid or Expired Token"
            });
        }

        // Update password

        user.password =
            await bcrypt.hash(newPassword, 10);

        // Remove reset fields

        user.resetPasswordToken = undefined;

        user.resetPasswordExpires = undefined;

        await user.save();

        return res.json({
            message: "Password Reset Successful"
        });

    } catch (error) {

        return res.status(500).json({
            error: error.message
        });
    }
});

// ====================== LOGIN PAGE ROUTE ======================

app.get("/login", (req, res) => {

    return res.status(401).json({
        message: "Please login to continue"
    });
});

// ====================== SERVER ======================

app.listen(PORT, () => {

    console.log(`🚀 Server started at port ${PORT}`);
});