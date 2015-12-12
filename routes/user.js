var express = require('express');
var crypto = require('crypto');
var session = require('express-session');
var passport = require('passport');
var LocalStrategy = require('passport-local').Strategy;
var router = express.Router();
var flash = require('express-flash');
var db = require('../db');

// larger numbers mean better security, less
var config = {
  // size of the generated hash
  hashBytes: 32,
  // larger salt means hashed passwords are more resistant to rainbow table, but
  // you get diminishing returns pretty fast
  saltBytes: 16,
  // more iterations means an attacker has to take longer to brute force an
  // individual password, so larger is better. however, larger also means longer
  // to hash the password. tune so that hashing the password takes about a
  // second
  iterations: 872791,

  registrationSuccess: 'Registration was successful!',
  registrationInfo: 'Further information has been sent to you email address.',
  loginSuccess: 'Login was successful! Welcome back',
  loginFailure: 'Pass word or username is incorrect. Please try again.'
};

passport.use('local', new LocalStrategy(
  function(username, password, done) {
    console.log(username);
    var next = function() {};
    db.get('users').findOne({ username: username }, function (err, user, next) {
      if (err) { console.log(err); return done(err); }
      if (!user) { console.log('No user found'); return done(null, false); }
      //if (!user.verifyPassword(password)) { return done(null, false); }
      console.log('User found!');
      console.log(user);
      return done(null, user);
    });
  }
));

passport.serializeUser(function(user, done) {
  done(null, user);
});

passport.deserializeUser(function(user, done) {
  done(null, user);
});

/* GET home page. */
router.get('/', function(req, res, next) {
  res.render('index', { title: 'User' });
});


router.get('/register', function(req, res, next){
	res.render('register', {messages: req.flash()});
});


// POST method route
router.post('/register', function (req, res, next) {
  //res.send('Registration complete');

  // Set initial DB var
  var db = req.db;

  // Get our form values
  var user = {
    name: req.body.username,
    email: req.body.useremail,
    pass: req.body.password,
  };

  // Arguments to pass to password hashing
  var arguments = {
    req: req,
    res: res,
    next: next,
    user: user,
    db: db
  }

  hashPassword(arguments, insertUser);
});


router.get('/login', function(req, res, next){
	res.render('login');
});

// POST method route
router.post('/login', 
  passport.authenticate('local', { failureRedirect: '/user/login' }),
  function(req, res) {
    req.flash('success', 'login successful');
    res.redirect('/');
  }
);

/**
 * Hash a password using Node's asynchronous pbkdf2 (key derivation) function.
 *
 * Returns a self-contained buffer which can be arbitrarily encoded for storage
 * that contains all the data needed to verify a password.
 *
 * @param {!String} password
 * @param {!function(?Error, ?Buffer=)} callback
 */
function hashPassword(input, callback) {
  // generate a salt for pbkdf2
  crypto.randomBytes(config.saltBytes, function(err, salt) {
    if (err) {
      return callback(err);
    }

    crypto.pbkdf2(input.user.pass, salt, config.iterations, config.hashBytes,
      function(err, hash) {

        if (err) {
          return callback(err);
        }

        var combined = new Buffer(hash.length + salt.length + 8);

        // include the size of the salt so that we can, during verification,
        // figure out how much of the hash is salt
        combined.writeUInt32BE(salt.length, 0, true);
        // similarly, include the iteration count
        combined.writeUInt32BE(config.iterations, 4, true);

        salt.copy(combined, 8);
        hash.copy(combined, salt.length + 8);

        callback(input, combined);
      }
    );
  });
}

function insertUser() {
  // Set our collection
  var input = arguments[0];
  var hash = arguments[1];
  var users = input.db.get('users');


  // Submit user to db
  users.insert({
    "username" : input.user.name,
    "useremail" : input.user.email,
    "password" : hash.toString('hex')
  }, function(err, doc) {
    if (err) {
      res.send('There was a problem adding the user to the DB.');
    }
    else {
      // Forward to the success page
      input.req.flash('success', config.registrationSuccess);
      input.req.flash('info', config.registrationInfo);
      input.res.redirect("/");
    }
  });
}

module.exports = router;