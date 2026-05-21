const authorizeRoles = (...roles) => {

    return (req, res, next) => {

        try {

            // ====================== CHECK USER ======================

            if (!req.user) {

                return res.status(401).json({

                    success: false,

                    message:
                        "User not authenticated"
                });
            }

            // ====================== CHECK ROLE ======================

            if (!roles.includes(req.user.role)) {

                return res.status(403).json({

                    success: false,

                    message:
                        "Access denied. Insufficient permissions.",

                    yourRole: req.user.role,

                    allowedRoles: roles
                });
            }

            // ====================== ACCESS GRANTED ======================

            next();

        } catch (error) {

            return res.status(500).json({

                success: false,

                error: error.message
            });
        }
    };
};

module.exports = authorizeRoles;