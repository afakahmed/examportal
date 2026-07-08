const express = require('express');
const mongoose = require('mongoose');
const session = require('express-session');
const MongoStore = require('connect-mongo')(session);
const bcrypt = require('bcryptjs');
const path = require('path');

const app = express();

// Middleware for JSON & Base64 Payloads (up to 15MB)
app.use(express.json({ limit: '15mb' }));
app.use(express.urlencoded({ extended: true, limit: '15mb' }));

// MongoDB Connection
mongoose.connect('mongodb://localhost:27017/examPortal', { useNewUrlParser: true, useUnifiedTopology: true })
  .then(() => console.log('MongoDB Connected'))
  .catch(err => console.error('MongoDB Connection Error:', err));

// Session Configuration
app.use(session({
  secret: 'exam_portal_super_secret',
  resave: false,
  saveUninitialized: false,
  store: new MongoStore({ url: 'mongodb://localhost:27017/examPortal' })
}));

// View Engine Setup
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// -------------------- Mongoose Models -------------------- //

const departmentSchema = new mongoose.Schema({
  name: { type: String, unique: true }
});
const Department = mongoose.model('Department', departmentSchema);

const userSchema = new mongoose.Schema({
  name: String,
  email: { type: String, unique: true },
  password: String,
  role: { type: String, enum: ['admin', 'student'], default: 'student' },
  department: { type: mongoose.Schema.Types.ObjectId, ref: 'Department' },
  studentId: String,
  profilePhoto: String,
  wallet: { type: Number, default: 0 }
});

userSchema.pre('save', async function(next) {
  if (this.isModified('password')) {
    this.password = await bcrypt.hash(this.password, 10);
  }
  if (this.isNew && this.role === 'student') {
    const lastStudent = await User.findOne({ role: 'student' }).sort({ createdAt: -1 });
    let num = 1;
    if (lastStudent && lastStudent.studentId) {
      num = parseInt(lastStudent.studentId.replace('ST', '')) + 1;
    }
    this.studentId = 'ST' + String(num).padStart(4, '0');
  }
  next();
});
const User = mongoose.model('User', userSchema);

const examSchema = new mongoose.Schema({
  title: String,
  description: String,
  department: { type: mongoose.Schema.Types.ObjectId, ref: 'Department' },
  duration: Number,
  passingPercentage: Number,
  questions: [{
    type: { type: String, enum: ['mcq', 'file'] },
    questionText: String,
    questionFile: String,
    options: [String],
    correctAnswer: String,
    marks: Number
  }],
  createdBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  isActive: { type: Boolean, default: true }
});
const Exam = mongoose.model('Exam', examSchema);

const submissionSchema = new mongoose.Schema({
  exam: { type: mongoose.Schema.Types.ObjectId, ref: 'Exam' },
  user: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  answers: [{
    questionIndex: Number,
    selectedAnswer: String,
    answerFile: String
  }],
  score: Number,
  totalMarks: Number,
  percentage: Number,
  passed: Boolean,
  needsManualGrading: Boolean,
  startedAt: Date,
  submittedAt: Date,
  timeTaken: Number,
  isSubmitted: { type: Boolean, default: false }
});
const Submission = mongoose.model('Submission', submissionSchema);

const videoSchema = new mongoose.Schema({
  title: String,
  youtubeUrl: String
});
const Video = mongoose.model('Video', videoSchema);

const messageSchema = new mongoose.Schema({
  subject: String,
  body: String,
  toStudent: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  fromAdmin: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  createdAt: { type: Date, default: Date.now },
  read: { type: Boolean, default: false }
});
const Message = mongoose.model('Message', messageSchema);

// -------------------- Middleware -------------------- //

const auth = (req, res, next) => {
  if (!req.session.userId) return res.status(401).json({ msg: 'Unauthorized' });
  next();
};
const adminOnly = (req, res, next) => {
  if (!req.session.userId || req.session.role !== 'admin') return res.status(403).json({ msg: 'Forbidden' });
  next();
};

// -------------------- Routes -------------------- //

app.get('/', async (req, res) => {
  let user = null;
  if (req.session.userId) {
    user = await User.findById(req.session.userId).populate('department').select('-password');
  }
  res.render('index', { user });
});

// Auth Routes
app.post('/api/auth/register', async (req, res) => {
  try {
    const { name, email, password, role, department } = req.body;
    if (await User.findOne({ email })) return res.status(400).json({ msg: 'Email already exists' });
    const user = new User({ name, email, password, role, department });
    await user.save();
    req.session.userId = user._id;
    req.session.role = user.role;
    res.json({ msg: 'Registered successfully' });
  } catch (err) { res.status(500).json({ msg: err.message }); }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email });
    if (!user) return res.status(400).json({ msg: 'User not found' });
    if (!await bcrypt.compare(password, user.password)) return res.status(400).json({ msg: 'Invalid credentials' });
    req.session.userId = user._id;
    req.session.role = user.role;
    res.json({ msg: 'Logged in successfully' });
  } catch (err) { res.status(500).json({ msg: err.message }); }
});

app.post('/api/auth/logout', (req, res) => {
  req.session.destroy();
  res.json({ msg: 'Logged out' });
});

// Department Routes
app.get('/api/departments', auth, async (req, res) => res.json(await Department.find()));
app.post('/api/departments', auth, adminOnly, async (req, res) => {
  const dep = new Department({ name: req.body.name });
  await dep.save(); res.json(dep);
});
app.delete('/api/departments/:id', auth, adminOnly, async (req, res) => {
  await Department.findByIdAndDelete(req.params.id); res.json({ msg: 'Deleted' });
});

// User Routes
app.get('/api/users', auth, adminOnly, async (req, res) => {
  res.json(await User.find({ role: 'student' }).select('-password'));
});
app.put('/api/users/profile', auth, async (req, res) => {
  const user = await User.findById(req.session.userId);
  if (req.body.profilePhoto) user.profilePhoto = req.body.profilePhoto;
  if (req.body.name) user.name = req.body.name;
  await user.save();
  res.json({ msg: 'Profile updated' });
});

// Exam Routes
app.get('/api/exams', auth, async (req, res) => {
  let query = {};
  if (req.session.role === 'student') query.isActive = true;
  res.json(await Exam.find(query).populate('department'));
});
app.post('/api/exams', auth, adminOnly, async (req, res) => {
  const exam = new Exam({ ...req.body, createdBy: req.session.userId });
  await exam.save(); res.json(exam);
});
app.get('/api/exams/:id', auth, async (req, res) => res.json(await Exam.findById(req.params.id).populate('department')));
app.post('/api/exams/:id/questions', auth, adminOnly, async (req, res) => {
  const exam = await Exam.findById(req.params.id);
  exam.questions.push(req.body);
  await exam.save(); res.json(exam);
});
app.delete('/api/exams/:id/questions/:qIndex', auth, adminOnly, async (req, res) => {
  const exam = await Exam.findById(req.params.id);
  exam.questions.splice(req.params.qIndex, 1);
  await exam.save(); res.json(exam);
});

// Submission Routes
app.post('/api/submissions/start', auth, async (req, res) => {
  const { examId } = req.body;
  let submission = await Submission.findOne({ exam: examId, user: req.session.userId, isSubmitted: false });
  if (!submission) {
    submission = new Submission({ exam: examId, user: req.session.userId, startedAt: new Date(), isSubmitted: false });
    await submission.save();
  }
  res.json(submission);
});
app.post('/api/submissions/submit', auth, async (req, res) => {
  const { submissionId, answers } = req.body;
  const submission = await Submission.findById(submissionId);
  if (!submission) return res.status(404).json({ msg: 'Not found' });
  const exam = await Exam.findById(submission.exam);
  let score = 0, totalMarks = 0, needsManualGrading = false;
  
  exam.questions.forEach((q, index) => {
    totalMarks += q.marks;
    const ans = answers.find(a => a.questionIndex == index);
    submission.answers.push(ans || { questionIndex: index, selectedAnswer: null, answerFile: null });
    if (q.type === 'mcq') {
      if (ans && ans.selectedAnswer === q.correctAnswer) score += q.marks;
    } else if (q.type === 'file') {
      if (ans && ans.answerFile) needsManualGrading = true;
    }
  });
  
  submission.score = score;
  submission.totalMarks = totalMarks;
  submission.percentage = totalMarks > 0 ? (score / totalMarks) * 100 : 0;
  submission.passed = submission.percentage >= exam.passingPercentage;
  submission.needsManualGrading = needsManualGrading;
  submission.submittedAt = new Date();
  submission.timeTaken = (submission.submittedAt - submission.startedAt) / 1000;
  submission.isSubmitted = true;
  await submission.save();
  res.json(submission);
});
app.get('/api/submissions', auth, async (req, res) => {
  if (req.session.role === 'admin') {
    if (req.query.examId) return res.json(await Submission.find({ exam: req.query.examId }).populate('user').populate('exam'));
    res.json(await Submission.find().populate('user').populate('exam'));
  } else {
    res.json(await Submission.find({ user: req.session.userId, isSubmitted: true }).populate('exam'));
  }
});
app.put('/api/submissions/:id/grade', auth, adminOnly, async (req, res) => {
  const { score } = req.body;
  const sub = await Submission.findById(req.params.id);
  sub.score = score;
  sub.percentage = sub.totalMarks > 0 ? (score / sub.totalMarks) * 100 : 0;
  const exam = await Exam.findById(sub.exam);
  sub.passed = sub.percentage >= exam.passingPercentage;
  sub.needsManualGrading = false;
  await sub.save(); res.json(sub);
});

// Video Routes
app.get('/api/videos', auth, async (req, res) => res.json(await Video.find()));
app.post('/api/videos', auth, adminOnly, async (req, res) => {
  const vid = new Video(req.body); await vid.save(); res.json(vid);
});
app.delete('/api/videos/:id', auth, adminOnly, async (req, res) => {
  await Video.findByIdAndDelete(req.params.id); res.json({ msg: 'Deleted' });
});

// Message Routes
app.post('/api/messages', auth, adminOnly, async (req, res) => {
  const msg = new Message({ ...req.body, fromAdmin: req.session.userId });
  await msg.save(); res.json(msg);
});
app.get('/api/messages', auth, async (req, res) => {
  if (req.session.role === 'student') res.json(await Message.find({ toStudent: req.session.userId }));
  else res.json(await Message.find().populate('toStudent'));
});

// Start Server
app.listen(3000, () => console.log('Server running on http://localhost:3000'));
