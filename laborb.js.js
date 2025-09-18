// =====================================
// COMPLETE BACKEND FOR KAAMWALE PLATFORM
// =====================================

// =====================================
// 1. PROJECT STRUCTURE
// =====================================
/*
kaamwale-backend/
├── src/
│   ├── config/
│   │   ├── database.js
│   │   ├── redis.js
│   │   └── constants.js
│   ├── models/
│   │   ├── User.js
│   │   ├── Worker.js
│   │   ├── Customer.js
│   │   ├── Booking.js
│   │   ├── Review.js
│   │   ├── Payment.js
│   │   └── Notification.js
│   ├── controllers/
│   │   ├── auth.controller.js
│   │   ├── worker.controller.js
│   │   ├── customer.controller.js
│   │   ├── booking.controller.js
│   │   ├── payment.controller.js
│   │   └── review.controller.js
│   ├── routes/
│   │   ├── auth.routes.js
│   │   ├── worker.routes.js
│   │   ├── customer.routes.js
│   │   ├── booking.routes.js
│   │   └── payment.routes.js
│   ├── middleware/
│   │   ├── auth.js
│   │   ├── validation.js
│   │   ├── upload.js
│   │   └── errorHandler.js
│   ├── services/
│   │   ├── sms.service.js
│   │   ├── email.service.js
│   │   ├── payment.service.js
│   │   ├── notification.service.js
│   │   └── location.service.js
│   ├── utils/
│   │   ├── helpers.js
│   │   ├── validators.js
│   │   └── logger.js
│   └── server.js
├── .env
├── .gitignore
├── package.json
└── README.md
*/

// =====================================
// 2. PACKAGE.JSON
// =====================================
const packageJSON = `{
  "name": "kaamwale-backend",
  "version": "1.0.0",
  "description": "Backend API for KaamWale - Labor Hiring Platform",
  "main": "src/server.js",
  "scripts": {
    "start": "node src/server.js",
    "dev": "nodemon src/server.js",
    "test": "jest --coverage",
    "lint": "eslint src/",
    "seed": "node src/utils/seed.js"
  },
  "dependencies": {
    "express": "^4.18.2",
    "mongoose": "^7.5.0",
    "bcryptjs": "^2.4.3",
    "jsonwebtoken": "^9.0.2",
    "dotenv": "^16.3.1",
    "cors": "^2.8.5",
    "helmet": "^7.0.0",
    "express-rate-limit": "^6.10.0",
    "express-validator": "^7.0.1",
    "multer": "^1.4.5-lts.1",
    "multer-s3": "^3.0.1",
    "aws-sdk": "^2.1450.0",
    "razorpay": "^2.9.2",
    "twilio": "^4.18.0",
    "nodemailer": "^6.9.5",
    "winston": "^3.10.0",
    "morgan": "^1.10.0",
    "compression": "^1.7.4",
    "redis": "^4.6.8",
    "ioredis": "^5.3.2",
    "socket.io": "^4.5.2",
    "moment": "^2.29.4",
    "moment-timezone": "^0.5.43",
    "geolib": "^3.3.4",
    "sharp": "^0.32.5",
    "axios": "^1.5.0",
    "uuid": "^9.0.0",
    "express-async-handler": "^1.2.0"
  },
  "devDependencies": {
    "nodemon": "^3.0.1",
    "jest": "^29.7.0",
    "supertest": "^6.3.3",
    "eslint": "^8.48.0",
    "@faker-js/faker": "^8.0.2"
  },
  "engines": {
    "node": ">=16.0.0",
    "npm": ">=8.0.0"
  }
}`;

// =====================================
// 3. MAIN SERVER FILE
// =====================================
const serverFile = `
// src/server.js
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const helmet = require('helmet');
const compression = require('compression');
const morgan = require('morgan');
const rateLimit = require('express-rate-limit');
const http = require('http');
const socketIO = require('socket.io');
const path = require('path');
require('dotenv').config();

const app = express();
const server = http.createServer(app);
const io = socketIO(server, {
  cors: {
    origin: process.env.CLIENT_URL || 'http://localhost:3000',
    credentials: true
  }
});

// Import routes
const authRoutes = require('./routes/auth.routes');
const workerRoutes = require('./routes/worker.routes');
const customerRoutes = require('./routes/customer.routes');
const bookingRoutes = require('./routes/booking.routes');
const paymentRoutes = require('./routes/payment.routes');
const reviewRoutes = require('./routes/review.routes');

// Import middleware
const errorHandler = require('./middleware/errorHandler');
const { logger } = require('./utils/logger');

// Security middleware
app.use(helmet({
  crossOriginResourcePolicy: { policy: "cross-origin" }
}));

// CORS configuration
app.use(cors({
  origin: function(origin, callback) {
    const allowedOrigins = [
      'http://localhost:3000',
      'http://localhost:3001',
      process.env.CLIENT_URL
    ].filter(Boolean);
    
    if (!origin || allowedOrigins.indexOf(origin) !== -1) {
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS'));
    }
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With']
}));

// Body parsing middleware
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Compression middleware
app.use(compression());

// Logging middleware
app.use(morgan('combined', { stream: { write: message => logger.info(message.trim()) }}));

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // limit each IP to 100 requests per windowMs
  message: 'Too many requests from this IP, please try again later.',
  standardHeaders: true,
  legacyHeaders: false,
});

app.use('/api/', limiter);

// Strict rate limiting for auth endpoints
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  skipSuccessfulRequests: true
});

app.use('/api/auth/login', authLimiter);
app.use('/api/auth/register', authLimiter);

// Static files
app.use('/uploads', express.static(path.join(__dirname, '../uploads')));

// Database connection
mongoose.connect(process.env.MONGODB_URI || 'mongodb://localhost:27017/kaamwale', {
  useNewUrlParser: true,
  useUnifiedTopology: true,
})
.then(() => {
  logger.info('✅ Connected to MongoDB');
})
.catch(err => {
  logger.error('❌ MongoDB connection error:', err);
  process.exit(1);
});

// Redis connection
const { redisClient } = require('./config/redis');

// API Routes
app.use('/api/auth', authRoutes);
app.use('/api/workers', workerRoutes);
app.use('/api/customers', customerRoutes);
app.use('/api/bookings', bookingRoutes);
app.use('/api/payments', paymentRoutes);
app.use('/api/reviews', reviewRoutes);

// Health check endpoint
app.get('/api/health', (req, res) => {
  res.json({
    status: 'OK',
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
    environment: process.env.NODE_ENV || 'development'
  });
});

// Socket.io connection handling
io.on('connection', (socket) => {
  logger.info('New client connected:', socket.id);
  
  // Join user-specific room
  socket.on('join', (userId) => {
    socket.join(\`user_\${userId}\`);
    logger.info(\`User \${userId} joined room\`);
  });
  
  // Join worker-specific room for real-time job updates
  socket.on('join-worker', (workerId) => {
    socket.join(\`worker_\${workerId}\`);
  });
  
  // Handle booking updates
  socket.on('booking-update', (data) => {
    io.to(\`user_\${data.customerId}\`).emit('booking-status', data);
    io.to(\`worker_\${data.workerId}\`).emit('booking-status', data);
  });
  
  // Handle location updates from workers
  socket.on('location-update', (data) => {
    io.to(\`booking_\${data.bookingId}\`).emit('worker-location', data);
  });
  
  socket.on('disconnect', () => {
    logger.info('Client disconnected:', socket.id);
  });
});

// Error handling middleware (should be last)
app.use(errorHandler);

// Handle 404
app.use((req, res) => {
  res.status(404).json({
    success: false,
    message: 'Route not found'
  });
});

// Start server
const PORT = process.env.PORT || 5000;
server.listen(PORT, () => {
  logger.info(\`🚀 Server running on port \${PORT} in \${process.env.NODE_ENV || 'development'} mode\`);
});

// Export for testing
module.exports = { app, io };
`;

// =====================================
// 4. DATABASE MODELS
// =====================================
const userModel = `
// src/models/User.js
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');

const userSchema = new mongoose.Schema({
  phone: {
    type: String,
    required: true,
    unique: true,
    trim: true,
    match: [/^[6-9]\\d{9}$/, 'Please enter a valid Indian phone number']
  },
  email: {
    type: String,
    sparse: true,
    lowercase: true,
    match: [/^[\\w-\\.]+@([\\w-]+\\.)+[\\w-]{2,4}$/, 'Please enter a valid email']
  },
  password: {
    type: String,
    required: true,
    minlength: 6
  },
  role: {
    type: String,
    enum: ['customer', 'worker', 'admin'],
    required: true
  },
  isVerified: {
    type: Boolean,
    default: false
  },
  isActive: {
    type: Boolean,
    default: true
  },
  otp: {
    code: String,
    expiresAt: Date
  },
  resetPasswordToken: String,
  resetPasswordExpires: Date,
  lastLogin: Date,
  loginAttempts: {
    type: Number,
    default: 0
  },
  lockUntil: Date,
  deviceTokens: [String], // For push notifications
  preferences: {
    language: {
      type: String,
      enum: ['hi', 'en'],
      default: 'hi'
    },
    notifications: {
      sms: { type: Boolean, default: true },
      email: { type: Boolean, default: true },
      push: { type: Boolean, default: true }
    }
  }
}, {
  timestamps: true
});

// Indexes
userSchema.index({ phone: 1 });
userSchema.index({ email: 1 });
userSchema.index({ role: 1, isActive: 1 });

// Virtual for account lock
userSchema.virtual('isLocked').get(function() {
  return !!(this.lockUntil && this.lockUntil > Date.now());
});

// Hash password before saving
userSchema.pre('save', async function(next) {
  if (!this.isModified('password')) return next();
  
  try {
    const salt = await bcrypt.genSalt(12);
    this.password = await bcrypt.hash(this.password, salt);
    next();
  } catch (error) {
    next(error);
  }
});

// Compare password method
userSchema.methods.comparePassword = async function(candidatePassword) {
  return await bcrypt.compare(candidatePassword, this.password);
};

// Handle failed login attempts
userSchema.methods.incLoginAttempts = function() {
  // Reset attempts if lock has expired
  if (this.lockUntil && this.lockUntil < Date.now()) {
    return this.updateOne({
      $set: { loginAttempts: 1 },
      $unset: { lockUntil: 1 }
    });
  }
  
  const updates = { $inc: { loginAttempts: 1 } };
  const maxAttempts = 5;
  const lockTime = 2 * 60 * 60 * 1000; // 2 hours
  
  if (this.loginAttempts + 1 >= maxAttempts && !this.isLocked) {
    updates.$set = { lockUntil: Date.now() + lockTime };
  }
  
  return this.updateOne(updates);
};

// Reset login attempts
userSchema.methods.resetLoginAttempts = function() {
  return this.updateOne({
    $set: { loginAttempts: 0 },
    $unset: { lockUntil: 1 }
  });
};

module.exports = mongoose.model('User', userSchema);
`;

const workerModel = `
// src/models/Worker.js
const mongoose = require('mongoose');

const workerSchema = new mongoose.Schema({
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true,
    unique: true
  },
  fullName: {
    type: String,
    required: true,
    trim: true
  },
  photo: {
    type: String,
    default: null
  },
  dateOfBirth: Date,
  gender: {
    type: String,
    enum: ['male', 'female', 'other']
  },
  alternatePhone: String,
  address: {
    street: String,
    area: String,
    landmark: String,
    city: {
      type: String,
      required: true
    },
    state: {
      type: String,
      required: true,
      default: 'Madhya Pradesh'
    },
    pincode: {
      type: String,
      required: true,
      match: [/^[1-9][0-9]{5}$/, 'Please enter valid pincode']
    },
    coordinates: {
      type: {
        type: String,
        enum: ['Point'],
        default: 'Point'
      },
      coordinates: {
        type: [Number], // [longitude, latitude]
        default: [77.4126, 23.2599] // Bhopal coordinates
      }
    }
  },
  skills: {
    type: [{
      type: String,
      enum: ['plumber', 'electrician', 'carpenter', 'painter', 'cleaner', 'mason', 'ac_repair', 'appliance_repair', 'gardener', 'driver']
    }],
    required: true
  },
  primarySkill: {
    type: String,
    required: true
  },
  experience: {
    type: String,
    enum: ['0-1', '1-3', '3-5', '5+'],
    required: true
  },
  experienceDetails: String,
  certifications: [{
    name: String,
    issuer: String,
    date: Date,
    document: String
  }],
  pricing: {
    hourly: {
      type: Number,
      min: 0
    },
    daily: {
      type: Number,
      min: 0
    },
    monthly: {
      type: Number,
      min: 0
    },
    projectBasis: {
      type: Boolean,
      default: true
    },
    negotiable: {
      type: Boolean,
      default: true
    }
  },
  availability: {
    days: [{
      type: String,
      enum: ['monday', 'tuesday', 'wednesday', 'thursday', 'friday', 'saturday', 'sunday']
    }],
    timeSlots: [{
      day: String,
      slots: [{
        start: String, // "09:00"
        end: String    // "18:00"
      }]
    }],
    holidays: [Date],
    isAvailableNow: {
      type: Boolean,
      default: true
    }
  },
  documents: {
    aadharCard: {
      number: String,
      frontImage: String,
      backImage: String,
      isVerified: { type: Boolean, default: false }
    },
    panCard: {
      number: String,
      image: String,
      isVerified: { type: Boolean, default: false }
    },
    drivingLicense: {
      number: String,
      image: String,
      isVerified: { type: Boolean, default: false }
    },
    policeVerification: {
      certificateNumber: String,
      document: String,
      issuedDate: Date,
      expiryDate: Date,
      isVerified: { type: Boolean, default: false }
    }
  },
  bankDetails: {
    accountHolderName: String,
    accountNumber: String,
    ifscCode: String,
    bankName: String,
    branch: String,
    upiId: String
  },
  verification: {
    isProfileVerified: {
      type: Boolean,
      default: false
    },
    isDocumentsVerified: {
      type: Boolean,
      default: false
    },
    isBackgroundVerified: {
      type: Boolean,
      default: false
    },
    verificationDate: Date,
    verifiedBy: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User'
    },
    verificationNotes: String
  },
  rating: {
    average: {
      type: Number,
      default: 0,
      min: 0,
      max: 5
    },
    count: {
      type: Number,
      default: 0
    },
    distribution: {
      1: { type: Number, default: 0 },
      2: { type: Number, default: 0 },
      3: { type: Number, default: 0 },
      4: { type: Number, default: 0 },
      5: { type: Number, default: 0 }
    }
  },
  stats: {
    totalBookings: { type: Number, default: 0 },
    completedBookings: { type: Number, default: 0 },
    cancelledBookings: { type: Number, default: 0 },
    totalEarnings: { type: Number, default: 0 },
    currentMonthEarnings: { type: Number, default: 0 },
    responseRate: { type: Number, default: 100 },
    acceptanceRate: { type: Number, default: 0 },
    onTimeRate: { type: Number, default: 100 }
  },
  status: {
    type: String,
    enum: ['active', 'inactive', 'suspended', 'blacklisted'],
    default: 'inactive'
  },
  languages: {
    type: [String],
    default: ['Hindi']
  },
  serviceAreas: [{
    pincode: String,
    area: String,
    city: String
  }],
  equipment: {
    hasOwnTools: { type: Boolean, default: false },
    toolsList: [String]
  },
  preferences: {
    maxTravelDistance: { type: Number, default: 10 }, // in km
    preferredJobTypes: [String],
    minJobDuration: { type: Number, default: 1 }, // in hours
  },
  badges: [{
    type: String,
    enum: ['verified', 'top_rated', 'quick_responder', 'expert', 'trusted'],
    earnedAt: Date
  }],
  lastActive: Date,
  fcmToken: String, // For push notifications
  notes: String // Admin notes
}, {
  timestamps: true
});

// Indexes for efficient querying
workerSchema.index({ 'address.coordinates': '2dsphere' });
workerSchema.index({ status: 1, 'rating.average': -1 });
workerSchema.index({ skills: 1, status: 1 });
workerSchema.index({ 'address.city': 1, 'address.pincode': 1 });
workerSchema.index({ primarySkill: 1, status: 1 });

// Virtual for full address
workerSchema.virtual('fullAddress').get(function() {
  return \`\${this.address.street}, \${this.address.area}, \${this.address.city}, \${this.address.state} - \${this.address.pincode}\`;
});

// Method to update rating
workerSchema.methods.updateRating = async function(newRating) {
  const currentTotal = this.rating.average * this.rating.count;
  this.rating.count += 1;
  this.rating.average = (currentTotal + newRating) / this.rating.count;
  this.rating.distribution[newRating] += 1;
  
  // Award badges based on performance
  if (this.rating.average >= 4.5 && this.rating.count >= 20) {
    if (!this.badges.some(b => b === 'top_rated')) {
      this.badges.push({ type: 'top_rated', earnedAt: new Date() });
    }
  }
  
  await this.save();
};

module.exports = mongoose.model('Worker', workerSchema);
`;

const bookingModel = `
// src/models/Booking.js
const mongoose = require('mongoose');
const { v4: uuidv4 } = require('uuid');

const bookingSchema = new mongoose.Schema({
  bookingId: {
    type: String,
    unique: true,
    default: () => 'BK' + Date.now().toString(36).toUpperCase() + Math.random().toString(36).substr(2, 4).toUpperCase()
  },
  customerId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Customer',
    required: true
  },
  workerId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Worker',
    required: true
  },
  service: {
    type: String,
    required: true
  },
  serviceType: {
    type: String,
    enum: ['plumber', 'electrician', 'carpenter', 'painter', 'cleaner', 'mason', 'ac_repair', 'appliance_repair'],
    required: true
  },
  description: {
    type: String,
    required: true
  },
  requirements: {
    urgency: {
      type: String,
      enum: ['immediate', 'today', 'scheduled'],
      default: 'scheduled'
    },
    estimatedDuration: Number, // in hours
    numberOfWorkers: {
      type: Number,
      default: 1
    },
    materialRequired: {
      type: Boolean,
      default: false
    },
    specificRequirements: String
  },
  images: [{
    url: String,
    description: String,
    uploadedAt: {
      type: Date,
      default: Date.now
    }
  }],
  schedule: {
    date: {
      type: Date,
      required: true
    },
    timeSlot: {
      start: String, // "09:00"
      end: String    // "12:00"
    },
    flexible: {
      type: Boolean,
      default: false
    }
  },
  pricing: {
    type: {
      type: String,
      enum: ['hourly', 'daily', 'fixed', 'project'],
      required: true
    },
    rate: Number,
    estimatedHours: Number,
    estimatedCost: Number,
    finalCost: Number,
    materialCost: Number,
    platformFee: Number,
    gst: Number,
    discount: {
      amount: Number,
      code: String,
      type: String // 'percentage' or 'fixed'
    },
    total: Number,
    isPaid: {
      type: Boolean,
      default: false
    }
  },
  address: {
    type: {
      street: String,
      area: String,
      landmark: String,
      city: String,
      state: String,
      pincode: String
    },
    required: true
  },
  location: {
    type: {
      type: String,
      enum: ['Point'],
      default: 'Point'
    },
    coordinates: [Number] // [longitude, latitude]
  },
  status: {
    type: String,
    enum: [
      'pending',      // Customer created booking
      'accepted',     // Worker accepted
      'rejected',     // Worker rejected
      'confirmed',    // Customer confirmed after acceptance
      'in_progress',  // Work started
      'completed',    // Work completed
      'cancelled',    // Cancelled by either party
      'disputed'      // Dispute raised
    ],
    default: 'pending'
  },
  statusHistory: [{
    status: String,
    timestamp: Date,
    updatedBy: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User'
    },
    notes: String
  }],
  cancellation: {
    cancelledBy: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User'
    },
    reason: String,
    cancelledAt: Date,
    cancellationFee: Number
  },
  worker: {
    acceptedAt: Date,
    rejectedAt: Date,
    rejectionReason: String,
    arrivedAt: Date,
    startedAt: Date,
    completedAt: Date,
    notes: String,
    signature: String
  },
  customer: {
    confirmedAt: Date,
    signature: String,
    feedback: String
  },
  verification: {
    startOTP: {
      code: String,
      generatedAt: Date,
      verifiedAt: Date
    },
    endOTP: {
      code: String,
      generatedAt: Date,
      verifiedAt: Date
    }
  },
  tracking: {
    workerLocation: {
      type: {
        type: String,
        enum: ['Point']
      },
      coordinates: [Number]
    },
    lastUpdated: Date,
    estimatedArrival: Date,
    actualArrival: Date
  },
  payment: {
    method: {
      type: String,
      enum: ['cash', 'upi', 'card', 'netbanking', 'wallet'],
      default: 'cash'
    },
    transactionId: String,
    paidAt: Date,
    receipt: String
  },
  invoice: {
    number: String,
    generatedAt: Date,
    url: String
  },
  review: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Review'
  },
  isRecurring: {
    type: Boolean,
    default: false
  },
  recurringDetails: {
    frequency: {
      type: String,
      enum: ['daily', 'weekly', 'monthly']
    },
    endDate: Date,
    nextSchedule: Date
  },
  metadata: {
    source: {
      type: String,
      enum: ['web', 'mobile', 'call_center'],
      default: 'web'
    },
    deviceInfo: String,
    ipAddress: String
  }
}, {
  timestamps: true
});

// Indexes
bookingSchema.index({ bookingId: 1 });
bookingSchema.index({ customerId: 1, status: 1 });
bookingSchema.index({ workerId: 1, status: 1 });
bookingSchema.index({ 'schedule.date': 1 });
bookingSchema.index({ status: 1, createdAt: -1 });
bookingSchema.index({ location: '2dsphere' });

// Generate OTP
bookingSchema.methods.generateOTP = function(type) {
  const otp = Math.floor(100000 + Math.random() * 900000).toString();
  
  if (type === 'start') {
    this.verification.startOTP = {
      code: otp,
      generatedAt: new Date()
    };
  } else if (type === 'end') {
    this.verification.endOTP = {
      code: otp,
      generatedAt: new Date()
    };
  }
  
  return otp;
};

// Update status with history
bookingSchema.methods.updateStatus = async function(newStatus, userId, notes) {
  this.statusHistory.push({
    status: this.status,
    timestamp: new Date(),
    updatedBy: userId,
    notes
  });
  
  this.status = newStatus;
  await this.save();
};

module.exports = mongoose.model('Booking', bookingSchema);
`;

// =====================================
// 5. AUTHENTICATION CONTROLLER
// =====================================
const authController = `
// src/controllers/auth.controller.js
const asyncHandler = require('express-async-handler');
const User = require('../models/User');
const Worker = require('../models/Worker');
const Customer = require('../models/Customer');
const jwt = require('jsonwebtoken');
const { sendSMS } = require('../services/sms.service');
const { sendEmail } = require('../services/email.service');
const { generateOTP, generateToken } = require('../utils/helpers');
const { logger } = require('../utils/logger');

// Generate JWT tokens
const generateTokens = (userId, role) => {
  const accessToken =