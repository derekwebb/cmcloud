// Environment and configurations
var e = require('../env');
var u = require('../userUtil');
var keys = require('../keys');
var config = require('../config');

var express = require('express');
var crypto = require('crypto');
var session = require('express-session');
var passport = require('passport');
var router = express.Router();
var flash = require('express-flash');
var db = require('../db');

var Promise = require('promise');

// Authentication strategies
var LocalStrategy = require('passport-local').Strategy;
var GitHubStrategy = require('passport-github2').Strategy;


// Local authentication strategy
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


// Github authentication strategy
passport.use(new GitHubStrategy({
    clientID: keys.GITHUB_CLIENT_ID,
    clientSecret: keys.GITHUB_CLIENT_SECRET,
    callbackURL: "http://localhost:8090/user/auth/github/callback"
  },
  function(accessToken, refreshToken, profile, done) {
    
    // asynchronous verification
    process.nextTick(function () {

      profile = {github: profile};

      // @TODO, it would be nice to be able to search by _id here.
      db.get('users').find({ $or: [{username: profile.github.username}, {useremail: profile.github.emails[0].value}]}, function (err, user, next) {

        // Generate large unguessable password stand-in
        crypto.randomBytes(52, function(err, pass) {
          if (err) {
            return done(null, err);
          }
        
          // A new user
          if (user.length < 1) {
            var arguments = {
              user: { name: profile.github.username, email: profile.github.emails[0].value },
              profile: profile
            }
            user = insertUser(arguments, pass).query;
          }

          // A returning user
          else { // update profile
            upsertUserProfile(user, profile);
          }

          return done(null, (user[0]) ? user[0] : user);
        });
      });
    });
  }
));

// route middleware that will happen on every request
router.use(function(req, res, next) {

  console.log('---| Request recieved |---'); 

  // log each request to the console
  console.log(req.method, req.url);

  // continue doing what we were doing and go to the route
  next(); 
});


passport.serializeUser(function(user, done) {
  done(null, user);
});


passport.deserializeUser(function(user, done) {
  done(null, user);
});


// Get user register page
router.get('/register', u.isAnonymous, function(req, res, next){
	res.render('register', {
    title: 'Register',
    messages: req.flash(),
    user: (req.user) ? req.user : null
  });
});


// POST method route
router.post('/register', function (req, res, next) {
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
    user: user
  }

  hashPassword(arguments, insertUser);
});


// Base login page
router.get('/login', u.isAnonymous, function(req, res, next) {
	res.render('login', {
    title: 'Login', 
    messages: req.flash(),
    user: (req.user) ? req.user : null
  });
});


// Logout - destroy session
router.get('/logout', u.isAuthenticated, function(req, res, next) {
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
    req.flash('success', config.auth.local.loginSuccess);
    if (config.hasOwnProperty('loginWelcome')) {
      req.flash('success', config.auth.local.loginWelcome + ' ' + user.username);
    }
    res.redirect('/');
  }
);


// GET /auth/github
//   Use passport.authenticate() as route middleware to authenticate the
//   request.  The first step in GitHub authentication will involve redirecting
//   the user to github.com.  After authorization, GitHub will redirect the user
//   back to this application at /auth/github/callback
router.get('/auth/github',
  passport.authenticate('github', { scope: [ 'user:email' ] }),
  function(req, res){
    // The request will be redirected to GitHub for authentication, so this
    //  function will not be called.
  }
);

// GET /auth/github/callback
//   Use passport.authenticate() as route middleware to authenticate the
//   request.  If authentication fails, the user will be redirected back to the
//   login page.  Otherwise, the primary route function will be called,
//   which, in this example, will redirect the user to the home page.
router.get('/auth/github/callback', 
  passport.authenticate('github', { failureRedirect: '/user/login' }),
  function(req, res) {
    req.flash('success', config.auth.github.loginSuccess);
    res.redirect('/');
  }
);


// User profile
router.get('/:userid', u.isAuthenticated, function(req, res) {
  var promises = [];
  var users = db.get('users');
  var data = {};

  promises.push(new Promise(function (resolve, reject) {
    db.get('users').find({_id: req.params.userid}, function (err, d, next) {
      data['user'] = d[0];
      if (err) reject(err);
      else resolve(resolve);
    });
  }));

  promises.push(new Promise(function (resolve, reject) {
    db.get('profiles').find({_id: req.params.userid}, function (err, d, next) {
      data['profile'] = d[0];
      if (err) reject(err);
      else resolve(resolve);
    });
  }));

  Promise.all(promises).then(function(resolve) {
    res.render('profile', {
      title: 'Profile', 
      messages: req.flash(),
      user: (req.user) ? req.user : null,
      u: (data) ? data : 'No user found'
    });
  });
});


// Edit page for the user profile.
router.get('/:userid/edit', u.isAuthenticated, function(req, res) {
  if (req.params.userid == req.user._id) {

    db.get('users').find({_id: req.params.userid}, function (err, d, next) {
      if (err) reject(err);
      else {
        res.render('profile-edit', {
          title: 'Edit profile', 
          messages: req.flash(),
          user: (d[0]) ? d[0] : null
        });
      }
    });
  }
  else {
    u.accessDenied(req, res);
  }
});


router.post('/:userid/edit', u.isAuthenticated, function(req, res) {
  if (req.params.userid == req.user._id) {

    var promises = [];
    var users = db.get('users');
    var data = {};

    promises.push(new Promise(function (resolve, reject) {
      db.get('users').find({_id: req.user._id}, function (err, d, next) {
        data['user'] = d[0];
        data['user']['username'] = req.body['user-name'];
        data['user']['biography'] = req.body['profile-bio'];
        data['user']['showemail'] = req.body['show-email'];
        db.get('users').updateById(req.user._id, data['user']);
        if (err) reject(err);
        else resolve(resolve);
      });
    }));

    Promise.all(promises).then(function(resolve) {
      req.flash('success', config.auth.local.profileSaved);
      res.render('profile-edit', {
        title: 'Edit profile', 
        messages: req.flash(),
        user: (data['user']) ? data['user'] : null,
      });
    });
  }
  else {
    u.accessDenied(req, res);
  }
});

// Hash a password using Node's asynchronous pbkdf2 (key derivation) function.
//
// Returns a self-contained buffer which can be arbitrarily encoded for storage
// that contains all the data needed to verify a password.
//
// @param {!String} password
// @param {!function(?Error, ?Buffer=)} callback
function hashPassword(input, callback) {
  // generate a salt for pbkdf2
  crypto.randomBytes(Number(config.auth.local.saltBytes), function(err, salt) {
    if (err) {
      return callback(err);
    }
    input.salt = salt;

    crypto.pbkdf2(input.user.pass, salt, Number(config.auth.local.iterations), Number(config.auth.local.hashBytes),
      function(err, hash) {

        if (err) {
          return callback(err);
        }

        var combined = new Buffer(hash.length + salt.length + 8);

        // include the size of the salt so that we can, during verification,
        // figure out how much of the hash is salt
        combined.writeUInt32BE(salt.length, 0, true);
        // similarly, include the iteration count
        combined.writeUInt32BE(Number(config.auth.local.iterations), 4, true);

        salt.copy(combined, 8);
        hash.copy(combined, salt.length + 8);

        callback(input, combined);
      }
    );
  });
}


// @TODO: Make sure we can change the settings in config, and this still works...
//        Right now the numbers for access are hard-coded -_-
function verifyPassword(password, user) {
  var dbPass = user.password;
  var dbSalt = dbPass.substring(16, 16 + (Number(config.auth.local.saltBytes) * 2));
  var dbHash = dbPass.substring(16 + (Number(config.auth.local.saltBytes) * 2), 16 + (Number(config.auth.local.saltBytes) * 2) + (Number(config.auth.local.hashBytes) * 2));

  salt = new Buffer(dbSalt, "hex");

  var hash = crypto.pbkdf2Sync(password, salt, Number(config.auth.local.iterations), Number(config.auth.local.hashBytes));

  if (hash.toString('hex') === dbHash) {
    return true;
  }
  return false;
}


// Insert a use into the db
function insertUser(input, hash) {
  // Set our collection
  var users = db.get('users');
  var user = '';
  if (input.hasOwnProperty('user')) user = input.user;
  else user = input;

  // Submit user to db
  return users.insert({
    "username" : user.name,
    "useremail" : user.email,
    "password" : hash.toString('hex'),
    "created" : new Date().getTime()
  }, function(err, user) {
    if (err) {
      if (input.hasOwnProperty('res')) {
        input.res.send('There was a problem adding the user to the DB.');
      }
    }
    else {
      // Save profile information if any came in
      if (input.hasOwnProperty('profile')) {
        upsertUserProfile(user, input.profile)
      }

      // Forward to the success page
      if (input.hasOwnProperty('req') && input.hasOwnProperty('res')) {
        input.req.flash('success', config.auth.local.registrationSuccess);
        input.req.flash('success', config.auth.local.registrationInfo);
        input.res.redirect("/");
      }
    }
  });
}


// Profiles are gathered from authorization providers
//  like GitHub, BitBucket, etc...
function upsertUserProfile(user, profile) {
  // @TODO: What to do about multiple users returned!?
  if (user.length) user = user[0];
  
  var profiles = db.get('profiles');

  profile._id = user._id;
  profiles.update(
    {_id: user._id},
    profile,
    {upsert: true}
  );
}

module.exports = router;