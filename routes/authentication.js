const { Router } = require('express');
const router = new Router();

const User = require('./../models/user');
const bcryptjs = require('bcryptjs');

const nodemailer = require('nodemailer');

const routeGuard = require('./../middleware/route-guard');

const transport = nodemailer.createTransport({
  service: 'Gmail',
  auth: {
    user: process.env.NODEMAILER_EMAIL,
    pass: process.env.NODEMAILER_PASSWORD
  },
  tls: {
    rejectUnauthorized: false
  }
});

router.get('/', (req, res, next) => {
  res.render('index');
});

router.get('/sign-up', (req, res, next) => {
  res.render('sign-up');
});

const generateRandomToken = length => {
  const characters = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';
  let token = '';
  for (let i = 0; i < length; i++) {
    token += characters[Math.floor(Math.random() * characters.length)];
  }
  return token;
};

router.post('/sign-up', (req, res, next) => {
  const { name, email, password, status, confirmationToken } = req.body;
  const token = generateRandomToken(40);

  bcryptjs
    .hash(password, 10)
    .then(hash => {
      return User.create({
        name,
        email,
        passwordHash: hash,
        status,
        confirmationToken: token
      });
    })
    .then(user => {
      req.session.user = user._id;
      transport
        .sendMail({
          from: process.env.NODEMAILER_EMAIL,
          to: process.env.NODEMAILER_EMAIL, // CHANGE THIS // email,
          subject: 'Sign-up Confirmation',
          html: `
            <html>
              <body>
                <p>Please confirm your account:</p>
                <a href="http://localhost:3000/authentication/confirm-email?token=${token}">Confirmation Link</a>
              </body>
            </html>
          `
        })
        .then(result => {
          console.log('Email was sent successfuly.');
          console.log(result);
        })
        .catch(error => {
          console.log('There was an error sending the email.');
          console.log(error);
        });
      res.render('email-validation', { user });
    })
    .catch(error => {
      next(error);
    });
});

router.get('/authentication/confirm-email', (req, res, next) => {
  const { mailToken } = req.query.token;
  User.findOneAndUpdate(mailToken, { status: 'active' }).then(user => {
    res.render('confirmation', { user });
  });
});

router.get('/sign-in', (req, res, next) => {
  res.render('sign-in');
});

router.post('/sign-in', (req, res, next) => {
  let userId;
  const { email, password } = req.body;
  User.findOne({ email })
    .then(user => {
      if (!user) {
        return Promise.reject(new Error("There's no user with that email."));
      } else {
        userId = user._id;
        return bcryptjs.compare(password, user.passwordHash);
      }
    })
    .then(result => {
      if (result) {
        req.session.user = userId;
        res.redirect('/');
      } else {
        return Promise.reject(new Error('Wrong password.'));
      }
    })
    .catch(error => {
      next(error);
    });
});

router.post('/sign-out', (req, res, next) => {
  req.session.destroy();
  res.redirect('/');
});

router.get('/private', routeGuard, (req, res, next) => {
  res.render('private');
});

module.exports = router;
