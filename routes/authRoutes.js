const express = require("express");

const bcrypt = require("bcryptjs");

const jwt = require("jsonwebtoken");

// ====================== IMPORTS ======================

const User =
    require("../models/User");

const transporter =
    require("../config/transporter");

const googleClient =
    require("../config/googleClient");

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

            // ====================== GOOGLE ACCOUNT BLOCK ======================

            if (

                user.authProvider === "google" &&

                !user.password

            ) {

                return res.status(401).json({

                    message:
                        "Please login using Google"
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

            // ====================== TIME VALUES ======================

            const otpExpiry =
                new Date(
                    Date.now() + 300000
                );

            const cooldownExpiry =
                new Date(
                    Date.now() + 60000
                );

            // ====================== ATOMIC UPDATE ======================

            const updatedUser =
                await User.findOneAndUpdate(

                    {

                        _id:
                            user._id,

                        $or: [

                            {
                                otpCooldownExpires:
                                    {
                                        $exists: false
                                    }
                            },

                            {
                                otpCooldownExpires:
                                    null
                            },

                            {
                                otpCooldownExpires:
                                    {
                                        $lte: new Date()
                                    }
                            }
                        ]
                    },

                    {

                        $set: {

                            loginOtp:
                                otp,

                            loginOtpExpires:
                                otpExpiry,

                            otpCooldownExpires:
                                cooldownExpiry
                        }
                    },

                    {

                        new: true
                    }
                );

            // ====================== COOLDOWN BLOCK ======================

            if (!updatedUser) {

                const latestUser =
                    await User.findById(
                        user._id
                    );

                const secondsLeft =
                    Math.ceil(

                        (
                            latestUser
                                .otpCooldownExpires -
                            Date.now()
                        ) / 1000
                    );

                return res.status(429).json({

                    message:
                        `Please wait ${secondsLeft}s before requesting another OTP`
                });
            }

            // ====================== SEND OTP EMAIL ======================

            await transporter.sendMail({

                from:
                    process.env.EMAIL_USER,

                to:
                    updatedUser.email,

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
                    updatedUser.email
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

            user.otpCooldownExpires =
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

// ====================== GOOGLE LOGIN ======================

router.post(

    "/google-login",

    async (req, res) => {

        try {

            const { token } =
                req.body;

            // ====================== VALIDATION ======================

            if (!token) {

                return res.status(400).json({

                    message:
                        "Google token is required"
                });
            }

            // ====================== VERIFY GOOGLE TOKEN ======================

            const ticket =
                await googleClient.verifyIdToken({

                    idToken:
                        token,

                    audience:
                        process.env.GOOGLE_CLIENT_ID
                });

            // ====================== GET PAYLOAD ======================

            const payload =
                ticket.getPayload();

            const {

                sub,
                email,
                name

            } = payload;

            // ====================== FIND USER ======================

            let user =
                await User.findOne({

                    email
                });

            // ====================== CREATE USER ======================

            if (!user) {

                user =
                    await User.create({

                        name,

                        email,

                        googleId:
                            sub,

                        authProvider:
                            "google",

                        isVerified:
                            true,

                        verifiedAt:
                            new Date()
                    });
            }

            // ====================== LINK GOOGLE ACCOUNT ======================

            if (

                user.authProvider === "local" &&

                !user.googleId

            ) {

                user.googleId =
                    sub;

                await user.save();
            }

            // ====================== GENERATE JWT ======================

            const jwtToken =
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
                    "Google Login Successful",

                token:
                    jwtToken,

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