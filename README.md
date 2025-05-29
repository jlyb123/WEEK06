# 🔐 Authentication API with Node.js & MongoDB

![Node.js](https://img.shields.io/badge/Node.js-18.x-green)
![Express](https://img.shields.io/badge/Express-4.x-lightgrey)
![MongoDB](https://img.shields.io/badge/MongoDB-6.x-green)

## 📝 Table of Contents
- [Features](#-features)
- [Installation](#-installation)
- [API Documentation](#-api-documentation)
- [Code Structure](#-code-structure)
- [Security](#-security)
- [Dependencies](#-dependencies)
- [License](#-license)

## 🌟 Features
- JWT authentication with role-based access control
- Secure password hashing with bcrypt
- Rate limiting for auth endpoints
- MongoDB integration with proper indexing
- Comprehensive error handling
- Health check endpoint

## 🚀 Installation

```bash
# Clone repository
git clone https://github.com/yourusername/auth-api.git
cd auth-api

# Install dependencies
npm install

# Create .env file
cp .env.example .env

# Start server
npm start
/**
 * @route POST /register
 * @desc Register new user
 * @access Public
 * @param {string} email - User email
 * @param {string} password - User password
 * @param {string} [role=user] - User role (user|admin|moderator|driver)
 * @returns {object} - Created user ID
 * @throws {400} - Missing fields
 * @throws {409} - Email exists
 */
app.post('/register', async (req, res) => {
  // Implementation...
});
/**
 * @route POST /auth/login
 * @desc User login
 * @access Public
 * @param {string} email - User email
 * @param {string} password - User password
 * @returns {object} - JWT token and user role
 * @throws {401} - Invalid credentials
 */
app.post('/auth/login', authLimiter, async (req, res) => {
  // Implementation...
});
/**
 * JWT Authentication Middleware
 * @middleware
 * @param {Request} req
 * @param {Response} res
 * @param {NextFunction} next
 */
function authenticate(req, res, next) {
  // Verify JWT token
  // Sets req.user if valid
}

### Key Features of This README:
1. **Code-Embedded Documentation** - Shows actual JSDoc comments from the code
2. **Visual Badges** - For quick tech stack identification
3. **Structured Sections** - Clear separation of concerns
4. **Security Highlights** - Emphasizes security practices
5. **Copy-Paste Friendly** - Ready-to-use installation commands
6. **Responsive Formatting** - Renders well on GitHub and other platforms

To generate API documentation from these JSDoc comments, you can use:
```bash
npm install -g jsdoc
jsdoc index.js -d docs