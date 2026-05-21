const express = require("express");

const bcrypt = require("bcryptjs");

const router = express.Router();

// ====================== ADMIN DASHBOARD ======================

router.get(
    "/admin-dashboard",

    auth,

    authorizeRoles("admin"),

    async (req, res) => {

        return res.json({

            success: true,

            message:
                "Welcome Admin Dashboard",

            user: req.user
        });
    }
);

// ====================== GET ALL USERS ======================

router.get(
    "/all-users",

    auth,

    authorizeRoles("admin"),

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

// ====================== APPROVE MANAGER ======================

router.put(
    "/approve-manager/:id",

    auth,

    authorizeRoles("admin"),

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

            user.role = "manager";

            user.managerRequestStatus =
                "approved";

            await user.save();

            return res.json({

                success: true,

                message:
                    "Manager request approved",

                user
            });

        } catch (error) {

            return res.status(500).json({

                error: error.message
            });
        }
    }
);

// ====================== REJECT MANAGER ======================

router.put(
    "/reject-manager/:id",

    auth,

    authorizeRoles("admin"),

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

router.put(
    "/change-password/:id",

    auth,

    authorizeRoles("admin"),

    async (req, res) => {

        try {

            const { newPassword } = req.body;

            if (!newPassword) {

                return res.status(400).json({

                    message:
                        "New Password is required"
                });
            }

            const user = await User.findById(
                req.params.id
            );

            if (!user) {

                return res.status(404).json({

                    message: "User not found"
                });
            }

            user.password =
                await bcrypt.hash(newPassword, 10);

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

module.exports = router;