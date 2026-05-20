# Login-API# JWT Authentication API

A Node.js Authentication System using:

- Express.js
- MongoDB
- JWT Authentication
- Email Verification
- Forgot Password
- Reset Password
- Protected Routes

This project also includes a temporary frontend built using plain HTML/CSS/JavaScript for local testing purposes.

---

# Features

## Authentication
- User Signup
- User Login
- JWT Token Authentication
- Protected Profile Route
- Logout

## Email Features
- Email Verification
- Forgot Password Email
- Reset Password Email

## User Features
- View Profile
- Update Profile

## Security
- Password Hashing using bcrypt
- JWT Token Validation
- Protected Middleware
- Token Expiration

---

# Tech Stack

## Backend
- Node.js
- Express.js
- MongoDB
- Mongoose
- JWT
- bcryptjs
- Nodemailer

## Frontend (Temporary)
- HTML
- CSS
- Vanilla JavaScript

---

# Project Structure

```bash
project/
│
├── index.js
├── package.json
├── package-lock.json
├── .env
├── README.md
│
├── style.css
│
├── index.html
├── signup.html
├── login.html
├── profile.html
├── update-profile.html
├── forgot-password.html
├── reset-password.html
├── verify-success.html
```

---

# Installation

## Clone Repository

```bash
git clone <your-github-repo-link>
```

## Open Project

```bash
cd project-folder
```

## Install Dependencies

```bash
npm install
```

---

# Environment Variables

Create `.env`

```env
PORT=8000

JWT_SECRET=your_secret_key

EMAIL_USER=your_email@gmail.com
EMAIL_PASS=your_app_password
```

---

# Run Project

```bash
node index.js
```

Server runs on:

```bash
http://localhost:8000
```

---

# MongoDB Setup

Default MongoDB URL:

```bash
mongodb://127.0.0.1:27017/authapp
```

Make sure MongoDB service is running locally.

---

# API Routes

## Authentication

### Signup

```http
POST /signup
```

### Login

```http
POST /login
```

### Verify Email

```http
GET /verify-email/:token
```

---

## Password Management

### Forgot Password

```http
POST /forgot-password
```

### Reset Password

```http
POST /reset-password/:token
```

---

## Profile

### Get Profile

```http
GET /profile
```

### Update Profile

```http
PUT /update_profile
```

---

# Frontend Note

The frontend included in this repository is temporary and intended only for local API testing and demonstration purposes.

The primary focus of this project is the backend authentication API architecture.

---

# Future Improvements

- React Frontend
- Refresh Tokens
- Role Based Authentication
- File Uploads
- OAuth Login
- Better UI/UX
- Docker Support
- Deployment

---

# Author

Chirag Agrawal
