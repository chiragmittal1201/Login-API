require("dotenv").config();

const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const crypto = require("crypto");
const nodemailer = require("nodemailer");
const cors = require("cors");

const authorizeRoles =
    require("./middleware/roleMiddleware");

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

        console.log(
            "MongoDB Connection Error:",
            err
        );
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

    // ====================== ROLE ======================

    role: {

        type: String,

        enum: [
            "user",
            "manager",
            "admin"
        ],

        default: "user"
    },

    // ====================== MANAGER REQUEST ======================

    managerRequestStatus: {

        type: String,

        enum: [
            "none",
            "pending",
            "approved",
            "rejected"
        ],

        default: "none"
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

const User = mongoose.model(
    "User",
    userSchema
);

// ====================== AUTH MIDDLEWARE ======================

const auth = async (req, res, next) => {

    try {

        let token =
            req.headers.authorization;

        if (!token) {

            return res.status(401).json({

                message:
                    "Please login first"
            });
        }

        if (token.startsWith("Bearer ")) {

            token =
                token.split(" ")[1];
        }

        const decoded =
            jwt.verify(
                token,
                JWT_SECRET
            );

        const user =
            await User.findById(
                decoded.id
            ).select("-password");

        if (!user) {

            return res.status(401).json({

                message:
                    "User not found"
            });
        }

        req.user = user;

        next();

    } catch (error) {

        return res.status(401).json({

            message:
                "Invalid or Expired Token"
        });
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

        // ====================== VALIDATION ======================

        const requiredFields = {

            name,
            email,
            phone,
            password
        };

        for (const field in requiredFields) {

            if (!requiredFields[field]) {

                return res.status(400).json({

                    message:
                        `${field} is required`
                });
            }
        }

        // ====================== CHECK USER ======================

        const existingUser =
            await User.findOne({

                $or: [

                    { email },

                    { phone }
                ]
            });

        if (existingUser) {

            return res.status(400).json({

                message:
                    "User Already Exists"
            });
        }

        // ====================== HASH PASSWORD ======================

        const hashedPassword =
            await bcrypt.hash(
                password,
                10
            );

        // ====================== VERIFY TOKEN ======================

        const verifyToken =
            crypto.randomBytes(32)
                .toString("hex");

        // ====================== CREATE USER ======================

        const user =
            await User.create({

                name,
                email,
                phone,
                address,
                state,
                city,

                password:
                    hashedPassword,

                verifyEmailToken:
                    verifyToken,

                verifyEmailExpires:
                    Date.now() + 3600000
            });

        // ====================== VERIFY LINK ======================

        const verifyLink =
            `http://localhost:${PORT}/verify-email/${verifyToken}`;

        // ====================== SEND EMAIL ======================

        await transporter.sendMail({

            from:
                process.env.EMAIL_USER,

            to: email,

            subject:
                "Verify Your Email",

            html: `

                <h2>Email Verification</h2>

                <p>
                    Click below to verify email
                </p>

                <a href="${verifyLink}">
                    ${verifyLink}
                </a>
            `
        });

        return res.status(201).json({

            success: true,

            message:
                "Signup Successful. Verification email sent.",

            user
        });

    } catch (error) {

        return res.status(500).json({

            error: error.message
        });
    }
});

// ====================== VERIFY EMAIL ======================

app.get(
    "/verify-email/:token",

    async (req, res) => {

        try {

            const user =
                await User.findOne({

                    verifyEmailToken:
                        req.params.token,

                    verifyEmailExpires: {

                        $gt: Date.now()
                    }
                });

            if (!user) {

                return res.status(400).json({

                    message:
                        "Invalid or Expired Token"
                });
            }

            user.isVerified = true;

            user.verifiedAt =
                new Date();

            user.verifyEmailToken =
                undefined;

            user.verifyEmailExpires =
                undefined;

            await user.save();

            return res.json({

                success: true,

                message:
                    "Email Verified Successfully"
            });

        } catch (error) {

            return res.status(500).json({

                error: error.message
            });
        }
    }
);

// ====================== LOGIN ======================

app.post("/login", async (req, res) => {

    try {

        const {

            emailOrPhone,
            password

        } = req.body;

        if (!emailOrPhone || !password) {

            return res.status(400).json({

                message:
                    "Email/Phone and Password are required"
            });
        }

        const user =
            await User.findOne({

                $or: [

                    {
                        email:
                            emailOrPhone
                    },

                    {
                        phone:
                            emailOrPhone
                    }
                ]
            });

        if (!user) {

            return res.status(401).json({

                message:
                    "Invalid Credentials"
            });
        }

        const isMatch =
            await bcrypt.compare(
                password,
                user.password
            );

        if (!isMatch) {

            return res.status(401).json({

                message:
                    "Invalid Credentials"
            });
        }

        if (!user.isVerified) {

            return res.status(401).json({

                message:
                    "Please verify email first"
            });
        }

        // ====================== TOKEN ======================

        const token =
            jwt.sign(

                {

                    id: user._id,

                    role: user.role
                },

                JWT_SECRET,

                {

                    expiresIn: "7d"
                }
            );

        return res.json({

            success: true,

            message:
                "Login Successful",

            token,

            role: user.role
        });

    } catch (error) {

        return res.status(500).json({

            error: error.message
        });
    }
});

// ====================== PROFILE ======================

app.get(
    "/profile",

    auth,

    async (req, res) => {

        return res.json({

            success: true,

            user: req.user
        });
    }
);

// ====================== UPDATE PROFILE ======================

app.put(
    "/update_profile",

    auth,

    async (req, res) => {

        try {

            const {

                name,
                phone,
                address,
                state,
                city

            } = req.body;

            const updatedUser =
                await User.findByIdAndUpdate(

                    req.user._id,

                    {

                        name,
                        phone,
                        address,
                        state,
                        city
                    },

                    {

                        returnDocument:
                            "after"
                    }
                ).select("-password");

            return res.json({

                success: true,

                message:
                    "Profile Updated",

                updatedUser
            });

        } catch (error) {

            return res.status(500).json({

                error: error.message
            });
        }
    }
);

// ====================== REQUEST MANAGER ACCESS ======================

app.post(
    "/request-manager-role",

    auth,

    authorizeRoles("user"),

    async (req, res) => {

        try {

            const user =
                await User.findById(
                    req.user._id
                );

            if (!user) {

                return res.status(404).json({

                    message:
                        "User not found"
                });
            }

            if (
                user.managerRequestStatus ===
                "pending"
            ) {

                return res.status(400).json({

                    message:
                        "Request already pending"
                });
            }

            user.managerRequestStatus =
                "pending";

            await user.save();

            return res.json({

                success: true,

                message:
                    "Manager request submitted"
            });

        } catch (error) {

            return res.status(500).json({

                error: error.message
            });
        }
    }
);

// ====================== REQUEST STATUS ======================

app.get(
    "/request-status",

    auth,

    async (req, res) => {

        return res.json({

            success: true,

            role:
                req.user.role,

            managerRequestStatus:
                req.user.managerRequestStatus
        });
    }
);

// ====================== ADMIN DASHBOARD ======================

app.get(
    "/admin-dashboard",

    auth,

    authorizeRoles("admin"),

    async (req, res) => {

        return res.json({

            success: true,

            message:
                "Welcome Admin",

            user: req.user
        });
    }
);

// ====================== MANAGER DASHBOARD ======================

app.get(
    "/manager-dashboard",

    auth,

    authorizeRoles(
        "manager",
        "admin"
    ),

    async (req, res) => {

        return res.json({

            success: true,

            message:
                "Welcome Manager",

            user: req.user
        });
    }
);

// ====================== GET ALL USERS ======================

app.get(
    "/all-users",

    auth,

    authorizeRoles(
        "admin",
        "manager"
    ),

    async (req, res) => {

        try {

            const users =
                await User.find()
                    .select("-password");

            return res.json({

                success: true,

                count: users.length,

                users
            });

        } catch (error) {

            return res.status(500).json({

                error: error.message
            });
        }
    }
);

// ====================== APPROVE MANAGER ======================

app.put(
    "/approve-manager/:id",

    auth,

    authorizeRoles("admin"),

    async (req, res) => {

        try {

            const user =
                await User.findById(
                    req.params.id
                );

            if (!user) {

                return res.status(404).json({

                    message:
                        "User not found"
                });
            }

            user.role = "manager";

            user.managerRequestStatus =
                "approved";

            await user.save();

            return res.json({

                success: true,

                message:
                    "Manager approved"
            });

        } catch (error) {

            return res.status(500).json({

                error: error.message
            });
        }
    }
);

// ====================== REJECT MANAGER ======================

app.put(
    "/reject-manager/:id",

    auth,

    authorizeRoles("admin"),

    async (req, res) => {

        try {

            const user =
                await User.findById(
                    req.params.id
                );

            if (!user) {

                return res.status(404).json({

                    message:
                        "User not found"
                });
            }

            user.managerRequestStatus =
                "rejected";

            await user.save();

            return res.json({

                success: true,

                message:
                    "Manager request rejected"
            });

        } catch (error) {

            return res.status(500).json({

                error: error.message
            });
        }
    }
);

// ====================== ADMIN CHANGE PASSWORD ======================

app.put(
    "/admin/change-password/:id",

    auth,

    authorizeRoles("admin"),

    async (req, res) => {

        try {

            const { newPassword } =
                req.body;

            if (!newPassword) {

                return res.status(400).json({

                    message:
                        "New password required"
                });
            }

            const user =
                await User.findById(
                    req.params.id
                );

            if (!user) {

                return res.status(404).json({

                    message:
                        "User not found"
                });
            }

            user.password =
                await bcrypt.hash(
                    newPassword,
                    10
                );

            await user.save();

            return res.json({

                success: true,

                message:
                    "Password changed successfully"
            });

        } catch (error) {

            return res.status(500).json({

                error: error.message
            });
        }
    }
);

// ====================== MANAGER SEND RESET LINK ======================

app.post(
    "/manager/send-reset-link/:id",

    auth,

    authorizeRoles(
        "manager",
        "admin"
    ),

    async (req, res) => {

        try {

            const user =
                await User.findById(
                    req.params.id
                );

            if (!user) {

                return res.status(404).json({

                    message:
                        "User not found"
                });
            }

            const resetToken =
                crypto.randomBytes(32)
                    .toString("hex");

            const hashedToken =
                crypto
                    .createHash("sha256")
                    .update(resetToken)
                    .digest("hex");

            user.resetPasswordToken =
                hashedToken;

            user.resetPasswordExpires =
                Date.now() + 3600000;

            await user.save();

            const resetLink =
                `http://127.0.0.1:5500/public/reset-password.html?token=${resetToken}`;

            await transporter.sendMail({

                from:
                    process.env.EMAIL_USER,

                to: user.email,

                subject:
                    "Manager Password Reset",

                html: `

                    <h2>Password Reset</h2>

                    <p>
                        Manager requested password reset.
                    </p>

                    <a href="${resetLink}">
                        ${resetLink}
                    </a>
                `
            });

            return res.json({

                success: true,

                message:
                    "Reset link sent successfully"
            });

        } catch (error) {

            return res.status(500).json({

                error: error.message
            });
        }
    }
);

// ====================== FORGOT PASSWORD ======================

app.post(
    "/forgot-password",

    async (req, res) => {

        try {

            const { email } =
                req.body;

            if (!email) {

                return res.status(400).json({

                    message:
                        "Email is required"
                });
            }

            const user =
                await User.findOne({
                    email
                });

            if (!user) {

                return res.status(404).json({

                    message:
                        "User not found"
                });
            }

            const resetToken =
                crypto.randomBytes(32)
                    .toString("hex");

            const hashedToken =
                crypto
                    .createHash("sha256")
                    .update(resetToken)
                    .digest("hex");

            user.resetPasswordToken =
                hashedToken;

            user.resetPasswordExpires =
                Date.now() + 3600000;

            await user.save();

            const resetLink =
                `http://127.0.0.1:5500/public/reset-password.html?token=${resetToken}`;

            await transporter.sendMail({

                from:
                    process.env.EMAIL_USER,

                to: user.email,

                subject:
                    "Reset Password",

                html: `

                    <h2>Password Reset</h2>

                    <a href="${resetLink}">
                        ${resetLink}
                    </a>
                `
            });

            return res.json({

                success: true,

                message:
                    "Reset link sent"
            });

        } catch (error) {

            return res.status(500).json({

                error: error.message
            });
        }
    }
);

// ====================== RESET PASSWORD ======================

app.post(
    "/reset-password/:token",

    async (req, res) => {

        try {

            const { newPassword } =
                req.body;

            if (!newPassword) {

                return res.status(400).json({

                    message:
                        "New password required"
                });
            }

            const hashedToken =
                crypto
                    .createHash("sha256")
                    .update(
                        req.params.token
                    )
                    .digest("hex");

            const user =
                await User.findOne({

                    resetPasswordToken:
                        hashedToken,

                    resetPasswordExpires: {

                        $gt: Date.now()
                    }
                });

            if (!user) {

                return res.status(400).json({

                    message:
                        "Invalid or expired token"
                });
            }

            user.password =
                await bcrypt.hash(
                    newPassword,
                    10
                );

            user.resetPasswordToken =
                undefined;

            user.resetPasswordExpires =
                undefined;

            await user.save();

            return res.json({

                success: true,

                message:
                    "Password reset successful"
            });

        } catch (error) {

            return res.status(500).json({

                error: error.message
            });
        }
    }
);

// ====================== LOGIN ROUTE ======================

app.get("/login", (req, res) => {

    return res.status(401).json({

        message:
            "Please login to continue"
    });
});

// ====================== SERVER ======================

app.listen(PORT, () => {

    console.log(
        `🚀 Server started at port ${PORT}`
    );
});