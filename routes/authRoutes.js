const express = require("express");

const bcrypt = require("bcryptjs");

const crypto = require("crypto");

const jwt = require("jsonwebtoken");

// ====================== IMPORTS ======================

const User =
    require("../models/User");

const transporter =
    require("../config/transporter");

// ====================== ROUTER ======================

const router =
    express.Router();

// ====================== LOGIN ======================

router.post(

    "/login",

    async (req, res) => {

        try {

            const {

                emailOrPhone,
                password

            } = req.body;

            // ====================== VALIDATION ======================

            if (

                !emailOrPhone ||

                !password

            ) {

                return res.status(400).json({

                    message:
                        "Email/Phone and Password are required"
                });
            }

            // ====================== FIND USER ======================

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

            // ====================== USER CHECK ======================

            if (!user) {

                return res.status(401).json({

                    message:
                        "Invalid Credentials"
                });
            }

            // ====================== PASSWORD CHECK ======================

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

            // ====================== EMAIL VERIFIED ======================

            if (!user.isVerified) {

                return res.status(401).json({

                    message:
                        "Please verify email first"
                });
            }

            // ====================== GENERATE OTP ======================

            const otp =
                Math.floor(

                    100000 +
                    Math.random() * 900000

                ).toString();

            // ====================== SAVE OTP ======================

            user.loginOtp =
                otp;

            user.loginOtpExpires =
                Date.now() + 300000;

            await user.save();

            // ====================== SEND OTP EMAIL ======================

            await transporter.sendMail({

                from:
                    process.env.EMAIL_USER,

                to:
                    user.email,

                subject:
                    "Login OTP Verification",

                html: `

                    <h2>Login OTP</h2>

                    <p>
                        Your OTP is:
                    </p>

                    <h1>
                        ${otp}
                    </h1>

                    <p>
                        OTP expires in 5 minutes.
                    </p>
                `
            });

            // ====================== RESPONSE ======================

            return res.json({

                success: true,

                message:
                    "OTP sent successfully",

                email:
                    user.email
            });

        } catch (error) {

            return res.status(500).json({

                error:
                    error.message
            });
        }
    }
);

// ====================== VERIFY LOGIN OTP ======================

router.post(

    "/verify-login-otp",

    async (req, res) => {

        try {

            const {

                email,
                otp

            } = req.body;

            // ====================== VALIDATION ======================

            if (

                !email ||

                !otp

            ) {

                return res.status(400).json({

                    message:
                        "Email and OTP are required"
                });
            }

            // ====================== FIND USER ======================

            const user =
                await User.findOne({

                    email
                });

            // ====================== USER CHECK ======================

            if (!user) {

                return res.status(404).json({

                    message:
                        "User not found"
                });
            }

            // ====================== OTP CHECK ======================

            if (

                user.loginOtp !== otp ||

                user.loginOtpExpires < Date.now()

            ) {

                return res.status(401).json({

                    message:
                        "Invalid or Expired OTP"
                });
            }

            // ====================== CLEAR OTP ======================

            user.loginOtp =
                undefined;

            user.loginOtpExpires =
                undefined;

            await user.save();

            // ====================== GENERATE JWT ======================

            const token =
                jwt.sign(

                    {

                        id:
                            user._id,

                        role:
                            user.role
                    },

                    process.env.JWT_SECRET,

                    {

                        expiresIn:
                            "7d"
                    }
                );

            // ====================== RESPONSE ======================

            return res.json({

                success: true,

                message:
                    "Login Successful",

                token,

                role:
                    user.role
            });

        } catch (error) {

            return res.status(500).json({

                error:
                    error.message
            });
        }
    }
);

// ====================== EXPORT ======================

module.exports = router;