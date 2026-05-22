const jwt = require("jsonwebtoken");

// ====================== IMPORT USER ======================

const User =
    require("../models/User");

// ====================== AUTH MIDDLEWARE ======================

const auth =
    async (req, res, next) => {

        try {

            let token =
                req.headers.authorization;

            // ====================== TOKEN CHECK ======================

            if (!token) {

                return res.status(401).json({

                    message:
                        "Please login first"
                });
            }

            // ====================== REMOVE BEARER ======================

            if (
                token.startsWith(
                    "Bearer "
                )
            ) {

                token =
                    token.split(" ")[1];
            }

            // ====================== VERIFY TOKEN ======================

            const decoded =
                jwt.verify(

                    token,

                    process.env.JWT_SECRET
                );

            // ====================== FIND USER ======================

            const user =
                await User.findById(
                    decoded.id
                )
                .select("-password");

            // ====================== USER CHECK ======================

            if (!user) {

                return res.status(401).json({

                    message:
                        "User not found"
                });
            }

            // ====================== SAVE USER ======================

            req.user = user;

            next();

        } catch (error) {

            return res.status(401).json({

                message:
                    "Invalid or Expired Token"
            });
        }
    };

// ====================== EXPORT ======================

module.exports = auth;