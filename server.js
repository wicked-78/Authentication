const express = require('express');
const app = express();
const bodyParser = require('body-parser');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');

app.use(bodyParser.json());

// Connect to MongoDB
mongoose.connect('mongodb://localhost/mydb', { useNewUrlParser: true });

// Create a user schema
const userSchema = new mongoose.Schema({
  email: {
    type: String,
    required: true,
    unique: true
  },
  password: {
    type: String,
    required: true
  }
});

// Hash the password before saving the user
userSchema.pre('save', function(next) {
  const user = this;
  if (!user.isModified('password')) {
    return next();
  }
  bcrypt.genSalt(10, (err, salt) => {
    if (err) {
      return next(err);
    }
    bcrypt.hash(user.password, salt, (err, hash) => {
      if (err) {
        return next(err);
      }
      user.password = hash;
      next();
    });
  });
});

// Create a model from the schema
const User = mongoose.model('User', userSchema);

// Signup route
app.post('/signup', (req, res) => {
  const { email, password } = req.body;
  const user = new User({ email, password });
  user.save((err) => {
    if (err) {
      return res.status(400).send(err);
    }
    res.send('User created successfully');
  });
});

// Login route
app.post('/login', (req, res) => {
  const { email, password } = req.body;
  User.findOne({ email }, (err, user) => {
    if (err) {
      return res.status(400).send(err);
    }
    if (!user) {
      return res.status(400).send('No user with that email');
    }
    bcrypt.compare(password, user.password, (err, isMatch) => {
      if (err) {
        return res.status(400).send(err);
      }
      if (!isMatch) {
        return res.status(400).send('Incorrect password');
      }
      res.send('Logged in successfully');
    });
  });
});

app.listen(3000, () => {
  console.log('Server listening on port 3000');
});
