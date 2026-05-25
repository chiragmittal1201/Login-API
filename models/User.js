const mongoose =
    require("mongoose");

// ====================== USER SCHEMA ======================

const userSchema =
    new mongoose.Schema({

        name: {

            type: String,

            required: true
        },

        email: {

            type: String,

            required: true,

            unique: true
        },

        phone: {

            type: String,

            required: true,

            unique: true
        },

        address: {

            type: String
        },

        state: {

            type: String
        },

        city: {

            type: String
        },

        password: {

            type: String,

            required: true
        },

        // ====================== ROLE ======================

        role: {

            type: String,

            enum: [

                "user",
                "manager",
                "admin"
            ],

            default: "user"
        },

        // ====================== MANAGER REQUEST ======================

        managerRequestStatus: {

            type: String,

            enum: [

                "none",
                "pending",
                "approved",
                "rejected"
            ],

            default: "none"
        },

        // ====================== EMAIL VERIFICATION ======================

        isVerified: {

            type: Boolean,

            default: false
        },

        verifiedAt: {

            type: Date
        },

        verifyEmailToken: {

            type: String
        },

        verifyEmailExpires: {

            type: Date
        },

        // ====================== PASSWORD RESET ======================

        resetPasswordToken: {

            type: String
        },

        resetPasswordExpires: {

            type: Date
        },

        // ====================== LOGIN OTP ======================

        loginOtp: {

            type: String
        },

        loginOtpExpires: {

            type: Date
        }

    }, {

        timestamps: true
    });

// ====================== MODEL ======================

const User =
    mongoose.model(

        "User",

        userSchema
    );

// ====================== EXPORT ======================

module.exports = User;