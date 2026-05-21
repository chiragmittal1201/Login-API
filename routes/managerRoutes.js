const express = require("express");

const crypto = require("crypto");

const router = express.Router();

// ====================== MANAGER DASHBOARD ======================

router.get(
    "/manager-dashboard",

    auth,

    authorizeRoles("manager", "admin"),

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

    authorizeRoles("manager", "admin"),

    async (req, res) => {

        try {

            const users = await User.find()
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

// ====================== SEND RESET LINK ======================

router.post(
    "/send-reset-link/:id",

    auth,

    authorizeRoles("manager", "admin"),

    async (req, res) => {

        try {

            const user = await User.findById(
                req.params.id
            );

            if (!user) {

                return res.status(404).json({

                    message: "User not found"
                });
            }

            // Generate token

            const resetToken =
                crypto.randomBytes(32)
                    .toString("hex");

            // Hash token

            const hashedToken = crypto
                .createHash("sha256")
                .update(resetToken)
                .digest("hex");

            // Save token

            user.resetPasswordToken =
                hashedToken;

            user.resetPasswordExpires =
                Date.now() + 3600000;

            await user.save();

            // Reset link

            const resetLink =
                `http://localhost:8000/reset-password/${resetToken}`;

            // Send email

            await transporter.sendMail({

                from: process.env.EMAIL_USER,

                to: user.email,

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

module.exports = router;