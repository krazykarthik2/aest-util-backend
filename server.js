const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const speakeasy = require('speakeasy');
const qrcode = require('qrcode');
const dotenv = require('dotenv');
const { protect } = require('./middleware/auth');
const User = require('./models/User');
const State = require('./models/State');

// Load env vars
dotenv.config();

const app = express();
const port = 5000;

console.log('NODE_ENV: ', process.env.NODE_ENV);
console.log('MONGODB_URI: ', process.env.MONGODB_URI);

// Connect to MongoDB
mongoose.connect(process.env.MONGODB_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true
})
.then(() => console.log('MongoDB Connected'))
.catch(err => console.error('MongoDB connection error:', err));

// Middleware
app.use(cors());
app.use(bodyParser.json());

// Auth routes
app.post('/auth/signup', async (req, res) => {
  try {
    const { email, password,name } = req.body;

    // Check if user exists
    let user = await User.findOne({ email });
    if (user) {
      return res.status(400).json({
        error: 'Bad Request',
        message: 'User already exists'
      });
    }

    // Generate TOTP secret
    const totpSecret = speakeasy.generateSecret();

    // Create user
    user = await User.create({
      email,
      password,
      name,
      totpSecret: totpSecret.base32,
      totpEnabled: false
    });

    // Create token
    const token = user.getSignedJwtToken();

    res.status(201).json({
      success: true,
      token
    });
  } catch (error) {
    console.error('Signup error:', error);
    res.status(500).json({
      error: 'Internal Server Error',
      message: error.message
    });
  }
});

app.post('/auth/login', async (req, res) => {
  try {
    const { email, password, totp } = req.body;

    // Validate email
    if (!email) {
      return res.status(400).json({
        error: 'Bad Request',
        message: 'Please provide an email'
      });
    }

    // Check for user
    const user = await User.findOne({ email }).select('+password +totpSecret');
    if (!user) {
      return res.status(401).json({
        error: 'Unauthorized',
        message: 'Invalid credentials'
      });
    }

    if (user.totpEnabled && totp) {

      const verified = speakeasy.totp.verify({
        secret: user.totpSecret,
        encoding: 'base32',
        token: totp
      });

      if (!verified) {
        return res.status(401).json({
          error: 'Unauthorized',
          message: 'Invalid TOTP code'
        });
      }
    } else {
      if (!password) {
        return res.status(400).json({
          error: 'Bad Request',
          message: 'Password is required'
        });
      }

      // Check password
      const isMatch = await user.matchPassword(password);
      if (!isMatch) {
        return res.status(401).json({
          error: 'Unauthorized',
          message: 'Invalid credentials'
        });
      }
    }

    // Create token
    const token = user.getSignedJwtToken();

    res.json({
      success: true,
      user,
      token
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({
      error: 'Internal Server Error',
      message: error.message
    });
  }
});

// Verify JWT token
app.post('/auth/verify', async (req, res) => {
  console.log('-verify');
  try {
    let token;

    if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
      token = req.headers.authorization.split(' ')[1];
    }

    if (!token) {
      return res.status(401).json({
        error: 'Unauthorized',
        message: 'No token provided'
      });
    }

    try {
      // Verify token
      const decoded = jwt.verify(token, process.env.JWT_SECRET);
      
      // Get user from database
      const user = await User.findById(decoded.id);
      
      if (!user) {
        return res.status(401).json({
          error: 'Unauthorized',
          message: 'User not found'
        });
      }

      res.json({
        success: true,
        user: {
          id: user._id,
          email: user.email,
          totpEnabled: user.totpEnabled
        }
      });
    } catch (err) {
      return res.status(401).json({
        error: 'Unauthorized',
        message: 'Token is invalid'
      });
    }
  } catch (error) {
    res.status(500).json({
      error: 'Internal Server Error',
      message: error.message
    });
  }
});

// Enable TOTP for a user
app.post('/auth/enable-totp', protect, async (req, res) => {
  console.log('-enable totp') 
  try {
    const { totp } = req.body;
     
    // Get user with TOTP secret
    const user = await User.findById(req.user.id).select('+totpSecret');

    // Verify first TOTP code
    const verified = speakeasy.totp.verify({
      secret: user.totpSecret,
      encoding: 'base32',
      token: totp
    });

    if (!verified) {
      return res.status(400).json({
        error: 'Bad Request',
        message: 'Invalid TOTP code'
      });
    }

    // Enable TOTP
    user.totpEnabled = true;
    await user.save();

    res.json({
      success: true,
      message: 'TOTP enabled successfully'
    });
  } catch (error) {
    console.error('Enable TOTP error:', error);
    res.status(500).json({
      error: 'Internal Server Error',
      message: error.message
    });
  }
});

// Protected routes
app.get('/api/load-state', protect, async (req, res) => {
  console.log('-load-state');
  try {
    const userState = await State.findOne({ uuid: req.user.uuid }).select('state');
    
    if (!userState) {
      return res.status(404).json({ 
        error: 'Not Found',
        message: 'No state data available' 
      });
    }
    res.json({ state: userState.state });
  } catch (error) {
    console.error('Error loading state:', error);
    res.status(500).json({ 
      error: 'Internal Server Error',
      message: 'Failed to load state' 
    });
  }
});

app.post('/api/sync-state', protect, async (req, res) => {
  console.log('-sync-state');
  try {
    const { state } = req.body;
    
    if (!state) {
      return res.status(400).json({ 
        error: 'Bad Request',
        message: 'State data is required' 
      });
    }
    const user_state = await State.findOne({ uuid: req.user.uuid });
    if (user_state) {
      await State.updateOne({ uuid: req.user.uuid }, { state: state, lastUpdated: new Date() });
    } else {
      await State.create({
        uuid: req.user.uuid,
        state: state,
        lastUpdated: new Date()
      });
    }

    res.json({ 
      success: true,
      message: 'State synchronized successfully' 
    });
  } catch (error) {
    console.error('Error syncing state:', error);
    res.status(500).json({ 
      error: 'Internal Server Error',
      message: 'Failed to sync state' 
    });
  }
});

app.get('/api/generate-totp', protect, async (req, res) => {
  console.log('-generate-totp');
  try {
    // Generate TOTP secret
    let totpSecret = req.user.totpSecret;
    if (!totpSecret) {
      totpSecret = speakeasy.generateSecret();
      await User.findByIdAndUpdate(req.user.id, { totpSecret: totpSecret.base32 });
    }
    res.json({ 
      secret: totpSecret.base32,
    });
  } catch (error) {
    console.error('Error generating TOTP:', error);
    res.status(500).json({ 
      error: 'Internal Server Error',
      message: 'Failed to generate TOTP' 
    });
  }
});
// Error handling middleware
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ 
    error: 'Internal Server Error',
    message: err.message 
  });
});

// Start server
app.listen(port, () => {
  console.log(`Server running at http://localhost:${port}`);
  console.log(`Environment: ${process.env.NODE_ENV}`);
  console.log(`MONGODB_URI: ${process.env.MONGODB_URI}`);
});
