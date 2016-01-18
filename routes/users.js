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


// GET users home page.
// @TODO: ----> Pagination! ---> Next()
router.get('/', u.isAuthenticated, function(req, res, next) {
  var promises = [];
  var data = {};
  var collated = {};
  var collateData = function(data) {
    for (user in data.users) {
      var userID = data.users[user]._id;
      
      // There is a better way to coollate the data here.
      //  Get profiles after the users and loop through 
      //  the users only once. Thus, the promises should be chained instead.
      var getUserProfile = function(userID, data) {
      	for (profile in data.profiles) {
      		if (data.profiles[profile]._id.toString() == userID.toString()) {
      			return data.profiles[profile];
      		}
      	}
      	return false;
      };

      collated[userID] = {
        user: data.users[user],
        profile: getUserProfile(userID, data)
      }
    }

    return collated;
  };

  promises.push(new Promise(function (resolve, reject) {
    db.get('users').find({}, function (err, d, next) {
      data['users'] = d;
      if (err) reject(err);
      else resolve(resolve);
    });
  }));

  promises.push(new Promise(function (resolve, reject) {
    db.get('profiles').find({}, function (err, d, next) {
      data['profiles'] = d;
      if (err) reject(err);
      else resolve(resolve);
    });
  }));

  Promise.all(promises).then(function(resolve) {
    // Collate data
    collated = collateData(data);

    res.render('users', { 
      title: 'Users', 
      messages: req.flash(),
      user: (req.user) ? req.user : null,
      profiles: collated
    });
  });
});

module.exports = router;
