// Environment and configurations
var e = require('../env');
var u = require('../userUtil');
var config = require('../config');

var express = require('express');
var router = express.Router();
var session = require('express-session');

/* GET home page. */
router.get('/', function(req, res, next) {
	res.render('index', { 
  	title: 'CMHome', 
  	messages: req.flash(),
  	user: (req.user) ? req.user : null
  });
});

/* GET About page. */
router.get('/about', function(req, res, next) {
	res.render('about', { 
  	title: 'About', 
  	messages: req.flash(),
  	user: (req.user) ? req.user : null
  });
});

module.exports = router;
