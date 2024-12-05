const mongoose = require('mongoose');

const StateSchema = new mongoose.Schema({
  uuid: {
    type: String,
    required: true,
    ref: 'User'
  },
  state: {
    type: mongoose.Schema.Types.Mixed,
    required: true
  },
  lastUpdated: {
    type: Date,
    default: Date.now
  }
});

// Create compound index for better query performance
StateSchema.index({ uuid: 1, lastUpdated: -1 });

module.exports = mongoose.model('State', StateSchema);
