const express = require('express');
const app = express();
const session = require('express-session');
const authRouter = require('./src/controllers/google-auth');
const protectedRouter = require('./src/controllers/protected-route');
const passport = require('passport');
const mongoose = require('mongoose');

require('dotenv').config();

app.set('view engine', 'ejs');

 

app.use(
  session({
    resave: false,
    saveUninitialized: true,
    secret: process.env.SESSION_SECRET,
  })
);

app.use(passport.initialize());
app.use(passport.session());

passport.serializeUser(function (user, cb) {
  cb(null, user);
});
passport.deserializeUser(function (obj, cb) {
  cb(null, obj);
});

app.get('/', (req, res) => {
  res.render('auth');
});

app.use('/auth/google', authRouter);
app.use('/protected', protectedRouter);

const port = process.env.PORT || 3000;
const start = async () => {
  try {
    await mongoose
      .connect(process.env.MONGODB_URI)
      .then(() => console.log('Connected to MongoDb..'))
      .catch((error) => {
        console.log('Error in connecting to mongoDB ' + error);
        throw error;
      });
    app.listen(port, () =>
      console.log(`Server is listening on port ${port}...`)
    );
  } catch (error) {
    console.log(error);
  }
};

start();
