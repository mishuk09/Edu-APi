const express = require('express');
const bodyParser = require('body-parser');
const mongoose = require('mongoose'); // Use mongoose for MongoDB
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const generateSecretKey = require('./keyGenerator'); // Import key generator

const app = express();
const port = 5000;

// Generate secret key
const secretKey = generateSecretKey();

// MongoDB connection
mongoose.connect('mongodb+srv://mishukinfo09:00hJuxkJdoA3kv9d@cluster0.onplo.mongodb.net/Auth', {
    useNewUrlParser: true,
    useUnifiedTopology: true,
}).then(() => console.log('MongoDB connected'))
    .catch((err) => console.log(err));

// User schema
const userSchema = new mongoose.Schema({
    firstName: { type: String, required: true },
    lastName: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    role: {
        type: String,
        enum: ['student', 'alumni', 'collegeAdmin', 'superAdmin'],
        default: 'student',  
    },
});

// Create a model from the schema
const User = mongoose.model('User', userSchema);

// Middleware
app.use(cors());
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// Verify token middleware
const verifyJWT = (req, res, next) => {
    const authHeader = req.headers.authorization;

    if (!authHeader) {
        return res.status(401).json({ message: 'Authorization header is missing' });
    }

    const token = authHeader.split(' ')[1];  

    jwt.verify(token, secretKey, (err, decoded) => {
        if (err) {
            return res.status(403).json({ message: 'Invalid token' });
        }

        // Token is valid
        req.userId = decoded.userId;  
        req.email = decoded.email;
        next();
    });
};

// Routes

// Signup route
app.post('/signup', async (req, res) => {
    try {
        const { firstName, lastName, email, password } = req.body;

        // Check if the user already exists
        const existingUser = await User.findOne({ email });
        if (existingUser) {
            return res.status(400).json({ message: 'User already exists' });
        }

        // Hash the password
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);

        // Create a new user with the default role (student)
        const newUser = new User({
            firstName,
            lastName,
            email,
            password: hashedPassword,
        });

        // Save the new user to the database
        await newUser.save();

        res.status(201).json(newUser);
    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server Error');
    }
});
// Signin route
app.post('/signin', async (req, res) => {
    try {
        const { email, password } = req.body;

        // Find the user by email
        const user = await User.findOne({ email });

        if (!user) {
            return res.status(401).json({ message: 'Invalid credentials' });
        }

        // Compare the password with the hashed password
        const validPassword = await bcrypt.compare(password, user.password);

        if (!validPassword) {
            return res.status(401).json({ message: 'Invalid credentials' });
        }

        // Generate JWT
        const token = jwt.sign(
            { userId: user._id, email: user.email },
            secretKey,
            { expiresIn: '1h' }
        );

        // Include the role in the response
        res.status(200).json({ token, role: user.role });
    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server Error');
    }
});




// Protected Routes


// Admin route (Accessible only to admins)
app.get('/admin', verifyJWT, async (req, res) => {
    try {
        const user = await User.findById(req.userId);

        if (user.role !== 'admin') {
            return res.status(403).json({ message: 'Access denied. Admins only.' });
        }

        res.status(200).json({ message: 'Welcome to Admin!' });
    } catch (err) {
        res.status(500).json({ message: 'Server error' });
    }
});

// Super Admin route (Accessible only to super-admins)
app.get('/super-admin', verifyJWT, async (req, res) => {
    try {
        const user = await User.findById(req.userId);

        if (user.role !== 'super-admin') {
            return res.status(403).json({ message: 'Access denied. Super Admins only.' });
        }

        res.status(200).json({ message: 'Welcome to Super Admin!' });
    } catch (err) {
        res.status(500).json({ message: 'Server error' });
    }
});

// Student route (Accessible only to students)
app.get('/student', verifyJWT, async (req, res) => {
    try {
        const user = await User.findById(req.userId);

        if (user.role !== 'student') {
            return res.status(403).json({ message: 'Access denied. Students only.' });
        }

        res.status(200).json({ message: 'Welcome to Student!' });
    } catch (err) {
        res.status(500).json({ message: 'Server error' });
    }
});



// Start server
app.listen(port, () => {
    console.log(`Server running on port ${port}`);
});
