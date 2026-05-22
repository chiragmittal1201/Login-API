const express = require("express");

const router = express.Router();

// ====================== IMPORTS ======================

const User =
    require("../models/User");

const authorizeRoles =
    require("../middleware/roleMiddleware");

const auth =
    require("../middleware/authMiddleware");

// ====================== REQUEST MANAGER ROLE ======================

router.post(

    "/request-manager-role",

    auth,

    authorizeRoles("user"),

    async (req, res) => {

        try {

            // ====================== FIND USER ======================

            const user =
                await User.findById(
                    req.user._id
                );

            // ====================== USER CHECK ======================

            if (!user) {

                return res.status(404).json({

                    message:
                        "User not found"
                });
            }

            // ====================== ALREADY MANAGER/ADMIN ======================

            if (

                user.role === "manager" ||

                user.role === "admin"

            ) {

                return res.status(400).json({

                    message:
                        "You already have elevated access"
                });
            }

            // ====================== REQUEST ALREADY PENDING ======================

            if (

                user.managerRequestStatus ===
                "pending"

            ) {

                return res.status(400).json({

                    message:
                        "Manager request already pending"
                });
            }

            // ====================== UPDATE REQUEST ======================

            user.managerRequestStatus =
                "pending";

            await user.save();

            // ====================== RESPONSE ======================

            return res.json({

                success: true,

                message:
                    "Manager access request submitted"
            });

        } catch (error) {

            return res.status(500).json({

                error:
                    error.message
            });
        }
    }
);

// ====================== CHECK REQUEST STATUS ======================

router.get(

    "/request-status",

    auth,

    async (req, res) => {

        try {

            // ====================== FIND USER ======================

            const user =
                await User.findById(
                    req.user._id
                );

            // ====================== USER CHECK ======================

            if (!user) {

                return res.status(404).json({

                    message:
                        "User not found"
                });
            }

            // ====================== RESPONSE ======================

            return res.json({

                success: true,

                role:
                    user.role,

                managerRequestStatus:
                    user.managerRequestStatus
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