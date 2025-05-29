const express = require('express');
const app = express();
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { MongoClient, ObjectId } = require('mongodb');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const morgan = require('morgan');
require('dotenv').config();

const port = process.env.PORT || 3000;
const saltRounds = 10;

// Security and logging middleware
app.use(helmet());
app.use(express.json());
app.use(morgan('dev'));

// Rate limiting
const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 5,
    message: "Too many requests, please try again later"
});

// MongoDB setup
async function main() {
    const requiredEnvVars = ['JWT_SECRET', 'MONGODB_URI'];
    for (const key of requiredEnvVars) {
        if (!process.env[key]) {
            throw new Error(`Missing environment variable: ${key}`);
        }
    }

    const client = new MongoClient(process.env.MONGODB_URI);
    await client.connect();
    const db = client.db('auth_demo');

    await db.collection('users').createIndex({ email: 1 }, { unique: true });

    function validatePassword(password) {
        return (
            password.length >= 8 &&
            /[A-Z]/.test(password) &&
            /[a-z]/.test(password) &&
            /\d/.test(password) &&
            /[!@#$%^&*]/.test(password)
        );
    }

    function authenticate(req, res, next) {
        const authHeader = req.headers['authorization'];
        const token = authHeader && authHeader.split(' ')[1];

        if (!token) return res.status(401).json({ error: 'Token required' });

        jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
            if (err) return res.status(403).json({ error: 'Invalid or expired token' });
            req.user = user;
            next();
        });
    }

    function authorize(roles = []) {
        return (req, res, next) => {
            if (!roles.includes(req.user.role)) {
                return res.status(403).json({
                    error: 'Access denied',
                    message: `Requires one of these roles: ${roles.join(', ')}`
                });
            }
            next();
        };
    }

    app.get('/health', (req, res) => {
        res.json({ status: 'OK', uptime: process.uptime() });
    });

    app.post('/register', async (req, res) => {
        const { email, password, role } = req.body;

        if (!email || !password) {
            return res.status(400).json({ error: 'Email and password required' });
        }

        if (!validatePassword(password)) {
            return res.status(400).json({ error: 'Password too weak' });
        }

        try {
            const hashed = await bcrypt.hash(password, saltRounds);
            const user = {
                email,
                password: hashed,
                role: ['admin', 'moderator', 'driver'].includes(role) ? role : 'user',
                createdAt: new Date(),
                lastLogin: null
            };

            const result = await db.collection('users').insertOne(user);
            res.status(201).json({ message: 'User registered', userId: result.insertedId });
        } catch (err) {
            if (err.code === 11000) {
                return res.status(409).json({ error: 'Email already exists' });
            }
            res.status(500).json({ error: 'Internal server error' });
        }
    });

    app.post('/auth/login', authLimiter, async (req, res) => {
        const { email, password } = req.body;

        const user = await db.collection('users').findOne({ email });
        if (!user) return res.status(401).json({ error: 'Invalid credentials' });

        const match = await bcrypt.compare(password, user.password);
        if (!match) return res.status(401).json({ error: 'Invalid credentials' });

        await db.collection('users').updateOne(
            { _id: user._id },
            { $set: { lastLogin: new Date() } }
        );

        const token = jwt.sign(
            { userId: user._id, email: user.email, role: user.role },
            process.env.JWT_SECRET,
            { expiresIn: '1h' }
        );

        res.json({ token, role: user.role, userId: user._id });
    });

    app.get('/profile', authenticate, async (req, res) => {
        const user = await db.collection('users').findOne(
            { _id: new ObjectId(req.user.userId) },
            { projection: { password: 0 } }
        );
        if (!user) return res.status(404).json({ error: 'User not found' });

        res.json(user);
    });

    // Updated endpoints to allow both admin and driver roles
    app.get('/admin', authenticate, authorize(['admin', 'driver']), (req, res) => {
        res.json({
            message: 'Admin/driver panel',
            user: req.user
        });
    });

    app.delete('/admin/users/:id', authenticate, authorize(['admin']), async (req, res) => {
        const { id } = req.params;

        if (!ObjectId.isValid(id)) return res.status(400).json({ error: 'Invalid ID format' });

        if (id === req.user.userId) {
            return res.status(403).json({ error: 'You cannot delete yourself' });
        }

        const result = await db.collection('users').deleteOne({ _id: new ObjectId(id) });
        if (result.deletedCount === 0) {
            return res.status(404).json({ error: 'User not found' });
        }

        res.status(204).send();
    });

    // New endpoint example for driver-specific access
    app.get('/driver/dashboard', authenticate, authorize(['admin', 'driver']), (req, res) => {
        res.json({
            message: 'Driver dashboard',
            user: req.user
        });
    });

    app.listen(port, () => {
        console.log(`Server running at http://localhost:${port}`);
    });
}

main().catch(err => {
    console.error('Failed to start server:', err);
    process.exit(1);
});