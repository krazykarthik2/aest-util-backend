const jwt = require('jsonwebtoken');
const User = require('../models/User');

exports.protect = async (req, res, next) => {
  try {
    let token;

    if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
      token = req.headers.authorization.split(' ')[1];
    }

    if (!token) {
      return res.status(401).json({
        error: 'Not authorized',
        message: 'Please login to access this resource'
      });
    }

    try {
      // Verify token
      const decoded = jwt.verify(token, process.env.JWT_SECRET);
      req.user = await User.findById(decoded.id).select('+uuid');
      
      if (!req.user) {
        return res.status(401).json({
          error: 'Not authorized',
          message: 'User not found'
        });
      }

      next();
    } catch (err) {
      return res.status(401).json({
        error: 'Not authorized',
        message: 'Token is invalid'
      });
    }
  } catch (error) {
    res.status(500).json({
      error: 'Internal Server Error',
      message: error.message
    });
  }
};
