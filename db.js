// Database connection
var mongo = require('mongodb');
var monk = require('monk');
var db = require('monk')('localhost/cmcloud');

module.exports = db;