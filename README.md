const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const bodyParser = require('body-parser');
require('dotenv').config();

const app = express();
app.use(bodyParser.json());

// MongoDB Connection
mongoose.connect(process.env.MONGO_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
}).then(() => console.log("MongoDB Connected"))
.catch(err => console.log(err));

// User Schema & Model
const UserSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
});

const User = mongoose.model('User', UserSchema);

// Generate JWT Token
const generateToken = (user) => {
    return jwt.sign(
        { userId: user._id, email: user.email },
        process.env.JWT_SECRET,
        { expiresIn: '1h' }
    );
};

// Signup Route
app.post('/auth/signup', async (req, res) => {
    try {
        const { username, email, password } = req.body;

        // Check if user already exists
        let user = await User.findOne({ email });
        if (user) return res.status(400).json({ msg: 'User already exists' });

        // Hash password
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);

        // Save user
        user = new User({ username, email, password: hashedPassword });
        await user.save();

        // Generate Token
        const token = generateToken(user);

        res.status(201).json({ msg: 'User registered successfully', token });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Login Route
app.post('/auth/login', async (req, res) => {
    try {
        const { email, password } = req.body;

        // Check if user exists
        let user = await User.findOne({ email });
        if (!user) return res.status(400).json({ msg: 'Invalid credentials' });

        // Check password
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) return res.status(400).json({ msg: 'Invalid credentials' });

        // Generate JWT Token
        const token = generateToken(user);

        res.json({ token });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Start Server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
