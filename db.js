// Environment and configurations
var e = require('./env');
var config = require('./config');

// Database connection
var mongo = require('mongodb');
var monk = require('monk');

var db = require('monk')(config.db[e.env.current].dbPath);

module.exports = db;