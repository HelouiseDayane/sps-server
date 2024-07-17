// routes.js

const express = require('express');
const jwt = require('jsonwebtoken');
const db = require('../db.json');

const router = express.Router();


router.post('/login', (req, res) => {
  const { email, password } = req.body;
  const user = db.users.find(u => u.email === email && u.password === password);
  if (!user) {
    return res.status(401).json({ message: 'Unauthorized' });
  }

  const token = jwt.sign({ email: user.email, type: user.type }, process.env.JWT_SECRET);
  res.json({ token });
});

function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ message: 'Unauthorized' });

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ message: 'Forbidden' });
    req.user = user;
    next();
  });
}


router.post('/users', authenticateToken, (req, res) => {
  const { email, name, type, password } = req.body;
  if (db.users.find(u => u.email === email)) {
    return res.status(400).json({ message: 'Email already registered' });
  }
  const newUser = { email, name, type, password };
  db.users.push(newUser);
  res.status(201).json(newUser);
});

router.get('/users', authenticateToken, (req, res) => {
  res.json(db.users);
});

router.put('/users/:email', authenticateToken, (req, res) => {
  const { email } = req.params;
  const { name, type, password } = req.body;
  const userIndex = db.users.findIndex(u => u.email === email);
  if (userIndex === -1) {
    return res.status(404).json({ message: 'User not found' });
  }
  db.users[userIndex] = { email, name, type, password };
  res.json(db.users[userIndex]);
});

router.delete('/users/:email', authenticateToken, (req, res) => {
  const { email } = req.params;
  const userIndex = db.users.findIndex(u => u.email === email);
  if (userIndex === -1) {
    return res.status(404).json({ message: 'User not found' });
  }
  db.users.splice(userIndex, 1);
  res.json({ message: 'User deleted' });
});

module.exports = router;
