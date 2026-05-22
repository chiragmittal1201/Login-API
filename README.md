# Login API

JWT-based authentication API built using Node.js, Express.js, and MongoDB.

This project includes authentication workflows such as signup, login, email verification, password reset, protected routes, profile management, and role-based access control (RBAC).

A lightweight frontend using HTML/CSS/JavaScript is included only for local API testing and demonstration purposes.

---

## Features

- User Signup & Login
- JWT Authentication
- Protected Routes
- Email Verification
- Forgot & Reset Password
- Profile Management
- Role-Based Access Control (RBAC)
- Password Hashing using bcrypt

---

## Tech Stack

- Node.js
- Express.js
- MongoDB
- Mongoose
- JWT
- bcryptjs
- Nodemailer
- HTML/CSS/JavaScript (Temporary Testing UI)

---

## Project Structure

```text
middleware/     -> Authentication & RBAC middleware
public/         -> Temporary frontend testing files
routes/         -> API route handlers
index.js        -> Main server entry point
```

---

## API Routes

| Method | Route |
|--------|-------|
| POST | /signup |
| POST | /login |
| GET | /verify-email/:token |
| POST | /forgot-password |
| POST | /reset-password/:token |
| GET | /profile |
| PUT | /update-profile |

---

## Installation

```bash
git clone <repo-link>
cd Login-API
npm install
```

---

## Environment Variables

Create a `.env` file:

```env
PORT=8000

JWT_SECRET=your_secret_key

EMAIL_USER=your_email@gmail.com
EMAIL_PASS=your_app_password
```

---

## Run Project

```bash
node index.js
```

Server runs on:

```text
http://localhost:8000
```

---

## Frontend Note

The frontend included in this repository is temporary and intended only for local API testing purposes.

The primary focus of this project is the backend authentication API architecture.

---

## Future Improvements

- Refresh Tokens
- OAuth Login
- Docker Support
- Deployment
- Better UI/UX
- Full React Frontend

---

## Status

Backend learning project focused on authentication workflows and secure API handling.
