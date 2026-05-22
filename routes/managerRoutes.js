const express = require("express");

const crypto = require("crypto");

const buildUserFilter =
    require("../utils/userFilter");

const authorizeRoles =
    require("../middleware/roleMiddleware");

const auth =
    require("../middleware/authMiddleware");

// ====================== IMPORTS FROM INDEX ======================

const User =
    require("../models/User");

const {

    transporter

} = require("../index");

const router = express.Router();

// ====================== MANAGER DASHBOARD ======================

router.get(

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
                "Welcome Manager Dashboard",

            user: req.user
        });
    }
);

// ====================== VIEW USERS ======================

router.get(

    "/view-users",

    auth,

    authorizeRoles(
        "manager",
        "admin"
    ),

    async (req, res) => {

        try {

            // ====================== BUILD FILTER ======================

            const filter =
                buildUserFilter(
                    req.query
                );

            // ====================== GET USERS ======================

            const users =
                await User.find(filter)
                    .select("-password");

            // ====================== RESPONSE ======================

            return res.json({

                success: true,

                count: users.length,

                users
            });

        } catch (error) {

            return res.status(500).json({

                error:
                    error.message
            });
        }
    }
);

// ====================== SEND RESET LINK ======================

router.post(

    "/send-reset-link/:id",

    auth,

    authorizeRoles(
        "manager",
        "admin"
    ),

    async (req, res) => {

        try {

            // ====================== FIND USER ======================

            const user =
                await User.findById(
                    req.params.id
                );

            // ====================== USER CHECK ======================

            if (!user) {

                return res.status(404).json({

                    message:
                        "User not found"
                });
            }

            // ====================== GENERATE TOKEN ======================

            const resetToken =
                crypto.randomBytes(32)
                    .toString("hex");

            // ====================== HASH TOKEN ======================

            const hashedToken =
                crypto
                    .createHash("sha256")
                    .update(resetToken)
                    .digest("hex");

            // ====================== SAVE TOKEN ======================

            user.resetPasswordToken =
                hashedToken;

            user.resetPasswordExpires =
                Date.now() + 3600000;

            await user.save();

            // ====================== RESET LINK ======================

            const resetLink =
                `http://127.0.0.1:5500/public/reset-password.html?token=${resetToken}`;

            // ====================== SEND EMAIL ======================

            await transporter.sendMail({

                from:
                    process.env.EMAIL_USER,

                to:
                    user.email,

                subject:
                    "Password Reset Request",

                html: `

                    <h2>Password Reset</h2>

                    <p>
                        A manager requested password reset.
                    </p>

                    <a href="${resetLink}">
                        ${resetLink}
                    </a>
                `
            });

            // ====================== RESPONSE ======================

            return res.json({

                success: true,

                message:
                    "Reset link sent successfully"
            });

        } catch (error) {

            return res.status(500).json({

                error:
                    error.message
            });
        }
    }
);

module.exports = router;