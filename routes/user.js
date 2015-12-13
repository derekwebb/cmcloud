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
  loginSuccess: 'Login was successful!',
  loginWelcome: 'Welcome back',
  loginFailure: 'Pass word or username is incorrect. Please try again.'
};

passport.use('local', new LocalStrategy(
  function(username, password, done) {
    var next = function() {};
    //db.inventory.find( { $or: [ { quantity: { $lt: 20 } }, { price: 10 } ] } )
    db.get('users').findOne({ $or: [{username: username}, {useremail: username}]}, function (err, user, next) {
      if (err) { console.log(err); return done(err); }
      if (!user) { console.log('No user found'); return done(null, false); }
      if (!verifyPassword(password, user)) { return done(null, false); }
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

/* GET user home page. */
router.get('/', function(req, res, next) {
  res.render('index', {
    title: 'Users',
    messages: req.flash(),
    user: (req.user) ? req.user : null
  });
});


/* Get user register page */
router.get('/register', function(req, res, next){
	res.render('register', {
    title: 'Register',
    messages: req.flash(),
    user: (req.user) ? req.user : null
  });
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


router.get('/login', function(req, res, next) {
	res.render('login', {
    title: 'Login', 
    messages: req.flash(),
    user: (req.user) ? req.user : null
  });
});

router.get('/logout', function(req, res, next) {
  req.session.destroy();
  res.redirect('/');
})

// POST method route
router.post('/login', 
  passport.authenticate('local', { 
    failureRedirect: '/user/login',
    failureFlash: 'Invalid username or password.'
  }),
  function(req, res) {
    var user = req.user;
    req.flash('success', config.loginSuccess);
    if (config.hasOwnProperty('loginWelcome')) {
      req.flash('success', config.loginWelcome + ' ' + user.username);
    }
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
    input.salt = salt;

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


function verifyPassword(password, user) {
  var dbPass = user.password;
  var dbSalt = dbPass.substring(16, 16 + (config.saltBytes * 2));
  var dbHash = dbPass.substring(16 + (config.saltBytes * 2), 16 + (config.saltBytes * 2) + (config.hashBytes * 2));

  salt = new Buffer(dbSalt, "hex");

  var hash = crypto.pbkdf2Sync(password, salt, config.iterations, config.hashBytes);

  if (hash.toString('hex') === dbHash) {
    return true;
  }
  return false;
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