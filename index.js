require("dotenv").config();

const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const crypto = require("crypto");
const nodemailer = require("nodemailer");
const cors = require("cors");
const transporter =
    require("./config/transporter");
// ====================== USER MODEL ======================

const User =
    require("./models/User");

// ====================== ROUTES ======================

const adminRoutes =
    require("./routes/adminRoutes");

const managerRoutes =
    require("./routes/managerRoutes");

const requestRoutes =
    require("./routes/requestRoutes");

const authRoutes =
    require("./routes/authRoutes");

// ====================== MIDDLEWARE ======================

const auth =
    require("./middleware/authMiddleware");

// ====================== APP ======================

const app = express();

const PORT = 8000;

// ====================== EXPRESS MIDDLEWARE ======================

app.use(cors({

    origin:
        "http://127.0.0.1:5500",

    credentials: true
}));

app.use(express.json());

app.use(express.urlencoded({

    extended: true
}));

// ====================== MONGODB CONNECTION ======================

mongoose.connect(
    "mongodb://127.0.0.1:27017/authapp"
)

.then(() => {

    console.log(
        "MongoDB Connected"
    );

})

.catch((err) => {

    console.log(
        "MongoDB Connection Error:",
        err
    );
});


// ====================== EXPORTS ======================

module.exports = {

    transporter
};

// ====================== SIGNUP ======================

app.post(
    "/signup",

    async (req, res) => {

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

            for (
                const field
                in requiredFields
            ) {

                if (
                    !requiredFields[field]
                ) {

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

                to:
                    email,

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

                error:
                    error.message
            });
        }
    }
);

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

                error:
                    error.message
            });
        }
    }
);

// ====================== PROFILE ======================

app.get(
    "/profile",

    auth,

    async (req, res) => {

        return res.json({

            success: true,

            user:
                req.user
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
                )
                .select("-password");

            return res.json({

                success: true,

                message:
                    "Profile Updated",

                updatedUser
            });

        } catch (error) {

            return res.status(500).json({

                error:
                    error.message
            });
        }
    }
);

// ====================== USE ROUTES ======================

app.use(
    "/admin",
    adminRoutes
);

app.use(
    "/manager",
    managerRoutes
);

app.use(
    "/request",
    requestRoutes
);

app.use(
    "/auth",
    authRoutes
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

                to:
                    user.email,

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

                error:
                    error.message
            });
        }
    }
);

// ====================== RESET PASSWORD ======================

app.post(
    "/reset-password/:token",

    async (req, res) => {

        try {

            const {

                newPassword

            } = req.body;

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

                error:
                    error.message
            });
        }
    }
);

// ====================== LOGIN ROUTE ======================

app.get(
    "/login",

    (req, res) => {

        return res.status(401).json({

            message:
                "Please login to continue"
        });
    }
);

// ====================== SERVER ======================

app.listen(PORT, () => {

    console.log(
        `🚀 Server started at port ${PORT}`
    );
});