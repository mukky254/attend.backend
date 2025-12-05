const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const dotenv = require('dotenv');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const QRCode = require('qrcode');
const { v4: uuidv4 } = require('uuid');
const moment = require('moment');

// Load environment variables
dotenv.config();

const app = express();

// Middleware
app.use(cors({
  origin: ['http://localhost:3000', process.env.FRONTEND_URL],
  credentials: true
}));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Database connection
mongoose.connect(process.env.MONGODB_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
})
.then(() => console.log('MongoDB connected successfully'))
.catch(err => console.error('MongoDB connection error:', err));

// Database Models

// User Schema
const userSchema = new mongoose.Schema({
  user_id: { type: String, unique: true },
  name: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  role: { 
    type: String, 
    enum: ['student', 'lecturer', 'admin', 'class_rep'], 
    required: true 
  },
  department: { type: String },
  student_id: { type: String, unique: true, sparse: true },
  lecturer_id: { type: String, unique: true, sparse: true },
  enrolled_courses: [{ type: mongoose.Schema.Types.ObjectId, ref: 'Course' }],
  created_at: { type: Date, default: Date.now },
  last_login: { type: Date }
});

// Course Schema
const courseSchema = new mongoose.Schema({
  course_code: { type: String, required: true, unique: true },
  course_name: { type: String, required: true },
  lecturer: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  department: { type: String, required: true },
  credits: { type: Number, default: 3 },
  schedule: [{
    day: { type: String, enum: ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday'] },
    start_time: String,
    end_time: String,
    venue: String
  }],
  students: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
  class_reps: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
  created_at: { type: Date, default: Date.now }
});

// Class Session Schema
const classSessionSchema = new mongoose.Schema({
  session_id: { type: String, unique: true, default: () => uuidv4() },
  course: { type: mongoose.Schema.Types.ObjectId, ref: 'Course', required: true },
  lecturer: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  date: { type: Date, required: true },
  start_time: { type: String, required: true },
  end_time: { type: String, required: true },
  venue: { type: String, required: true },
  status: { 
    type: String, 
    enum: ['scheduled', 'ongoing', 'completed', 'cancelled'], 
    default: 'scheduled' 
  },
  qr_code: {
    data: String,
    expiry: Date,
    is_active: { type: Boolean, default: true }
  },
  created_at: { type: Date, default: Date.now }
});

// Attendance Schema
const attendanceSchema = new mongoose.Schema({
  student: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  class_session: { type: mongoose.Schema.Types.ObjectId, ref: 'ClassSession', required: true },
  course: { type: mongoose.Schema.Types.ObjectId, ref: 'Course', required: true },
  scan_time: { type: Date, default: Date.now },
  status: { 
    type: String, 
    enum: ['present', 'late', 'absent', 'excused'], 
    default: 'present' 
  },
  scanned_by: { 
    type: String, 
    enum: ['qr_scan', 'manual', 'system'], 
    default: 'qr_scan' 
  },
  device_info: {
    user_agent: String,
    ip_address: String
  },
  location: {
    lat: Number,
    lng: Number
  }
});

// Create models
const User = mongoose.model('User', userSchema);
const Course = mongoose.model('Course', courseSchema);
const ClassSession = mongoose.model('ClassSession', classSessionSchema);
const Attendance = mongoose.model('Attendance', attendanceSchema);

// Auth Middleware
const authMiddleware = async (req, res, next) => {
  try {
    const token = req.header('Authorization')?.replace('Bearer ', '');
    
    if (!token) {
      return res.status(401).json({ error: 'No token provided' });
    }

    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const user = await User.findOne({ _id: decoded.userId });
    
    if (!user) {
      return res.status(401).json({ error: 'User not found' });
    }

    req.user = user;
    req.token = token;
    next();
  } catch (error) {
    res.status(401).json({ error: 'Invalid token' });
  }
};

// Role-based Middleware
const requireRole = (roles) => {
  return (req, res, next) => {
    if (!roles.includes(req.user.role)) {
      return res.status(403).json({ error: 'Access denied' });
    }
    next();
  };
};

// Routes

// Health Check
app.get('/api/health', (req, res) => {
  res.json({ 
    status: 'healthy', 
    timestamp: new Date().toISOString(),
    database: mongoose.connection.readyState === 1 ? 'connected' : 'disconnected'
  });
});

// Auth Routes
app.post('/api/auth/register', async (req, res) => {
  try {
    const { name, email, password, role, department, student_id, lecturer_id } = req.body;
    
    // Check if user exists
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ error: 'User already exists' });
    }

    // Hash password
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    // Create user
    const user = new User({
      user_id: uuidv4(),
      name,
      email,
      password: hashedPassword,
      role,
      department,
      student_id: role === 'student' ? student_id : null,
      lecturer_id: role === 'lecturer' ? lecturer_id : null
    });

    await user.save();

    // Create token
    const token = jwt.sign(
      { userId: user._id, email: user.email, role: user.role },
      process.env.JWT_SECRET,
      { expiresIn: process.env.JWT_EXPIRE }
    );

    res.status(201).json({
      success: true,
      token,
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
        role: user.role,
        department: user.department
      }
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    // Find user
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    // Check password
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    // Update last login
    user.last_login = new Date();
    await user.save();

    // Create token
    const token = jwt.sign(
      { userId: user._id, email: user.email, role: user.role },
      process.env.JWT_SECRET,
      { expiresIn: process.env.JWT_EXPIRE }
    );

    res.json({
      success: true,
      token,
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
        role: user.role,
        department: user.department,
        student_id: user.student_id,
        lecturer_id: user.lecturer_id
      }
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Course Routes
app.post('/api/courses', authMiddleware, requireRole(['lecturer', 'admin']), async (req, res) => {
  try {
    const { course_code, course_name, department, credits, schedule } = req.body;
    
    const course = new Course({
      course_code,
      course_name,
      lecturer: req.user._id,
      department,
      credits,
      schedule
    });

    await course.save();
    res.status(201).json({ success: true, course });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/courses', authMiddleware, async (req, res) => {
  try {
    let courses;
    
    if (req.user.role === 'lecturer') {
      courses = await Course.find({ lecturer: req.user._id }).populate('lecturer', 'name email');
    } else if (req.user.role === 'student') {
      courses = await Course.find({ students: req.user._id }).populate('lecturer', 'name email');
    } else {
      courses = await Course.find().populate('lecturer', 'name email');
    }

    res.json({ success: true, courses });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Class Session Routes
app.post('/api/classes', authMiddleware, requireRole(['lecturer', 'class_rep']), async (req, res) => {
  try {
    const { course_id, date, start_time, end_time, venue } = req.body;
    
    // Check if course exists and user has access
    const course = await Course.findById(course_id);
    if (!course) {
      return res.status(404).json({ error: 'Course not found' });
    }

    if (req.user.role === 'lecturer' && course.lecturer.toString() !== req.user._id.toString()) {
      return res.status(403).json({ error: 'Not authorized for this course' });
    }

    // Create class session
    const classSession = new ClassSession({
      course: course_id,
      lecturer: course.lecturer,
      date,
      start_time,
      end_time,
      venue,
      status: 'scheduled'
    });

    await classSession.save();
    
    // Generate QR code data
    const qrData = JSON.stringify({
      session_id: classSession.session_id,
      course_id: course_id,
      timestamp: new Date().toISOString()
    });

    // Generate QR code image
    const qrCodeImage = await QRCode.toDataURL(qrData);

    // Update class session with QR code
    classSession.qr_code = {
      data: qrCodeImage,
      expiry: new Date(Date.now() + 3 * 60 * 60 * 1000), // 3 hours expiry
      is_active: true
    };

    await classSession.save();

    res.status(201).json({ 
      success: true, 
      classSession,
      qr_code: classSession.qr_code.data
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/classes/today', authMiddleware, async (req, res) => {
  try {
    const today = new Date();
    today.setHours(0, 0, 0, 0);
    const tomorrow = new Date(today);
    tomorrow.setDate(tomorrow.getDate() + 1);

    let classes;
    
    if (req.user.role === 'lecturer') {
      classes = await ClassSession.find({
        lecturer: req.user._id,
        date: { $gte: today, $lt: tomorrow }
      }).populate('course', 'course_code course_name');
    } else if (req.user.role === 'student') {
      // Get student's enrolled courses
      const student = await User.findById(req.user._id).populate('enrolled_courses');
      const courseIds = student.enrolled_courses.map(course => course._id);
      
      classes = await ClassSession.find({
        course: { $in: courseIds },
        date: { $gte: today, $lt: tomorrow }
      }).populate('course', 'course_code course_name');
    } else {
      classes = await ClassSession.find({
        date: { $gte: today, $lt: tomorrow }
      }).populate('course', 'course_code course_name');
    }

    res.json({ success: true, classes });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// QR Code Routes
app.get('/api/classes/:sessionId/qr-code', authMiddleware, async (req, res) => {
  try {
    const classSession = await ClassSession.findOne({ 
      session_id: req.params.sessionId 
    }).populate('course', 'course_code course_name');

    if (!classSession) {
      return res.status(404).json({ error: 'Class session not found' });
    }

    // Check if user has access
    if (req.user.role === 'student') {
      const isEnrolled = await Course.findOne({
        _id: classSession.course._id,
        students: req.user._id
      });
      
      if (!isEnrolled) {
        return res.status(403).json({ error: 'Not enrolled in this course' });
      }
    }

    // Check if QR code is expired
    if (new Date() > classSession.qr_code.expiry) {
      classSession.qr_code.is_active = false;
      await classSession.save();
      return res.status(400).json({ error: 'QR code expired' });
    }

    res.json({ 
      success: true, 
      qr_code: classSession.qr_code.data,
      course: classSession.course,
      expiry: classSession.qr_code.expiry
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Attendance Routes
app.post('/api/attendance/scan', authMiddleware, requireRole(['student']), async (req, res) => {
  try {
    const { session_id, device_info, location } = req.body;

    // Find class session
    const classSession = await ClassSession.findOne({ session_id })
      .populate('course', 'course_code course_name students');
    
    if (!classSession) {
      return res.status(404).json({ error: 'Class session not found' });
    }

    // Check if QR code is active and not expired
    if (!classSession.qr_code.is_active || new Date() > classSession.qr_code.expiry) {
      return res.status(400).json({ error: 'QR code expired or inactive' });
    }

    // Check if student is enrolled
    const isEnrolled = classSession.course.students.some(
      student => student.toString() === req.user._id.toString()
    );
    
    if (!isEnrolled) {
      return res.status(403).json({ error: 'Not enrolled in this course' });
    }

    // Check if already marked attendance
    const existingAttendance = await Attendance.findOne({
      student: req.user._id,
      class_session: classSession._id
    });

    if (existingAttendance) {
      return res.status(400).json({ error: 'Attendance already marked' });
    }

    // Determine status (present/late)
    const classStartTime = new Date(`${classSession.date.toISOString().split('T')[0]}T${classSession.start_time}`);
    const currentTime = new Date();
    const minutesLate = (currentTime - classStartTime) / (1000 * 60);
    
    let status = 'present';
    if (minutesLate > 15) {
      status = 'late';
    }

    // Create attendance record
    const attendance = new Attendance({
      student: req.user._id,
      class_session: classSession._id,
      course: classSession.course._id,
      scan_time: currentTime,
      status,
      scanned_by: 'qr_scan',
      device_info,
      location
    });

    await attendance.save();

    res.json({
      success: true,
      message: 'Attendance marked successfully',
      attendance: {
        id: attendance._id,
        course: classSession.course.course_code,
        time: attendance.scan_time,
        status: attendance.status
      }
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/attendance/my-attendance', authMiddleware, requireRole(['student']), async (req, res) => {
  try {
    const attendance = await Attendance.find({ student: req.user._id })
      .populate({
        path: 'class_session',
        populate: {
          path: 'course',
          select: 'course_code course_name'
        }
      })
      .sort({ scan_time: -1 });

    res.json({ success: true, attendance });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/attendance/course/:courseId', authMiddleware, async (req, res) => {
  try {
    const { courseId } = req.params;
    
    // Check if user has access
    const course = await Course.findById(courseId);
    if (!course) {
      return res.status(404).json({ error: 'Course not found' });
    }

    if (req.user.role === 'lecturer' && course.lecturer.toString() !== req.user._id.toString()) {
      return res.status(403).json({ error: 'Access denied' });
    }

    const attendance = await Attendance.find({ course: courseId })
      .populate('student', 'name student_id email')
      .populate('class_session')
      .sort({ scan_time: -1 });

    res.json({ success: true, attendance });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Dashboard Routes
app.get('/api/dashboard/stats', authMiddleware, async (req, res) => {
  try {
    let stats = {};
    const userId = req.user._id;
    
    if (req.user.role === 'student') {
      // Student stats
      const totalClasses = await ClassSession.countDocuments({
        course: { $in: req.user.enrolled_courses },
        date: { $lt: new Date() }
      });
      
      const attendedClasses = await Attendance.countDocuments({
        student: userId
      });
      
      stats = {
        total_classes: totalClasses,
        attended_classes: attendedClasses,
        attendance_rate: totalClasses > 0 ? ((attendedClasses / totalClasses) * 100).toFixed(2) : 0
      };
    } else if (req.user.role === 'lecturer') {
      // Lecturer stats
      const courses = await Course.find({ lecturer: userId });
      const courseIds = courses.map(course => course._id);
      
      const totalSessions = await ClassSession.countDocuments({
        course: { $in: courseIds }
      });
      
      const totalStudents = await User.countDocuments({
        role: 'student',
        enrolled_courses: { $in: courseIds }
      });
      
      stats = {
        total_courses: courses.length,
        total_sessions: totalSessions,
        total_students: totalStudents
      };
    }

    res.json({ success: true, stats });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ error: 'Something went wrong!' });
});

// Start server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
