require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const bodyParser = require('body-parser');
const methodOverride = require('method-override');
const session = require('express-session');
const passport = require('passport');
const LocalStrategy = require('passport-local');
const bcrypt = require('bcryptjs');
const expressLayouts = require('express-ejs-layouts');

const Blog = require('./models/blog');
const User = require('./models/user');

const app = express();

// Database connection
mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log("Connected to MongoDB"))
  .catch(err => console.error("MongoDB connection error:", err));

// Middleware
app.set('view engine', 'ejs');
app.use(expressLayouts);
app.set('layout', 'layout');
app.use(express.static('public'));
app.use(bodyParser.urlencoded({ extended: true }));
app.use(methodOverride('_method'));

// Session configuration
app.use(session({
  secret: process.env.SESSION_SECRET || 'your-secret-key-here',
  resave: false,
  saveUninitialized: false,
  cookie: { 
    secure: process.env.NODE_ENV === 'production', 
    maxAge: 24 * 60 * 60 * 1000 // 1 day
  }
}));

// Passport initialization
app.use(passport.initialize());
app.use(passport.session());

// Passport configuration
passport.use(new LocalStrategy(
  async (username, password, done) => {
    try {
      const user = await User.findOne({ username });
      if (!user) return done(null, false, { message: 'Incorrect username.' });
      
      const isValid = await user.comparePassword(password);
      if (!isValid) return done(null, false, { message: 'Incorrect password.' });
      
      return done(null, user);
    } catch (err) {
      return done(err);
    }
  }
));

passport.serializeUser((user, done) => {
  done(null, user.id);
});

passport.deserializeUser(async (id, done) => {
  try {
    const user = await User.findById(id);
    done(null, user);
  } catch (err) {
    done(err);
  }
});

// Make current user available to all views
app.use((req, res, next) => {
  res.locals.currentUser = req.user;
  next();
});

// Authentication middleware
const isAuthenticated = (req, res, next) => {
  if (req.isAuthenticated()) return next();
  res.redirect('/login');
};

// Routes
// Home page - show all blogs
app.get('/', async (req, res) => {
  try {
    const blogs = await Blog.find().sort({ createdAt: -1 }).populate('author');
    res.render('index', { blogs });
  } catch (err) {
    console.error(err);
    res.status(500).send('Server Error');
  }
});

// Authentication Routes
app.get('/signup', (req, res) => {
  res.render('signup', { error: 'User already exists' });

});

app.post('/signup', async (req, res) => {
  try {
    const { username, email, password } = req.body;
    const user = new User({ username, email, password });
    await user.save();
    req.login(user, (err) => {
      if (err) return next(err);
      return res.redirect('/');
    });
  } catch (err) {
    res.render('signup', { error: err.message });
  }
});

app.get('/login', (req, res) => {
  res.render('login');
});

app.post('/login', passport.authenticate('local', {
  successRedirect: '/',
  failureRedirect: '/login'
}));

app.get('/logout', (req, res) => {
  req.logout();
  res.redirect('/');
});

// Blog Routes
app.get('/blogs/new', isAuthenticated, (req, res) => {
  res.render('new');
});

app.post('/blogs', isAuthenticated, async (req, res) => {
  try {
    const { title, content } = req.body;
    const blog = new Blog({
      title,
      content,
      author: req.user._id
    });
    await blog.save();
    res.redirect('/');
  } catch (err) {
    console.error(err);
    res.status(500).send('Server Error');
  }
});

app.get('/blogs/:id', async (req, res) => {
  try {
    const blog = await Blog.findById(req.params.id).populate('author');
    res.render('show', { blog });
  } catch (err) {
    console.error(err);
    res.status(404).send('Blog not found');
  }
});

app.get('/blogs/:id/edit', isAuthenticated, async (req, res) => {
  try {
    const blog = await Blog.findById(req.params.id);
    // Check if current user is the author
    if (!blog.author.equals(req.user._id)) {
      return res.redirect('/');
    }
    res.render('edit', { blog });
  } catch (err) {
    console.error(err);
    res.status(404).send('Blog not found');
  }
});

app.put('/blogs/:id', isAuthenticated, async (req, res) => {
  try {
    const blog = await Blog.findById(req.params.id);
    // Check if current user is the author
    if (!blog.author.equals(req.user._id)) {
      return res.redirect('/');
    }
    await Blog.findByIdAndUpdate(req.params.id, req.body);
    res.redirect('/');
  } catch (err) {
    console.error(err);
    res.status(500).send('Server Error');
  }
});

app.delete('/blogs/:id', isAuthenticated, async (req, res) => {
  try {
    const blog = await Blog.findById(req.params.id);
    // Check if current user is the author
    if (!blog.author.equals(req.user._id)) {
      return res.redirect('/');
    }
    await Blog.findByIdAndDelete(req.params.id);
    res.redirect('/');
  } catch (err) {
    console.error(err);
    res.status(500).send('Server Error');
  }
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).send('Something broke!');
});

// Start server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));