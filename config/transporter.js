const nodemailer =
    require("nodemailer");

// ====================== TRANSPORTER ======================

const transporter =
    nodemailer.createTransport({

        service: "gmail",

        auth: {

            user:
                process.env.EMAIL_USER,

            pass:
                process.env.EMAIL_PASS
        }
    });

// ====================== EXPORT ======================

module.exports =
    transporter;