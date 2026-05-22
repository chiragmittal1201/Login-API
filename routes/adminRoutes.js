const express = require("express");

const bcrypt = require("bcryptjs");

const buildUserFilter =
    require("../utils/userFilter");

const authorizeRoles =
    require("../middleware/roleMiddleware");

    const auth =
    require("../middleware/authMiddleware");

// ====================== IMPORTS FROM INDEX ======================

const User =
    require("../models/User");

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

// ====================== APPROVE MANAGER ======================

router.put(

    "/approve-manager/:id",

    auth,

    authorizeRoles("admin"),

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

            // ====================== UPDATE ROLE ======================

            user.role =
                "manager";

            user.managerRequestStatus =
                "approved";

            await user.save();

            // ====================== RESPONSE ======================

            return res.json({

                success: true,

                message:
                    "Manager request approved",

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

// ====================== REJECT MANAGER ======================

router.put(

    "/reject-manager/:id",

    auth,

    authorizeRoles("admin"),

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

            // ====================== UPDATE STATUS ======================

            user.managerRequestStatus =
                "rejected";

            await user.save();

            // ====================== RESPONSE ======================

            return res.json({

                success: true,

                message:
                    "Manager request rejected"
            });

        } catch (error) {

            return res.status(500).json({

                error:
                    error.message
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

            const {

                newPassword

            } = req.body;

            // ====================== VALIDATION ======================

            if (!newPassword) {

                return res.status(400).json({

                    message:
                        "New Password is required"
                });
            }

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

            // ====================== HASH PASSWORD ======================

            user.password =
                await bcrypt.hash(
                    newPassword,
                    10
                );

            await user.save();

            // ====================== RESPONSE ======================

            return res.json({

                success: true,

                message:
                    "Password changed successfully"
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