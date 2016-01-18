var userUtil = {};

// As with any middleware it is quintessential to call next()
// if the user is authenticated
userUtil.isAuthenticated = function (req, res, next) {
  if (req.isAuthenticated())
    return next();
  res.redirect('/');
}

userUtil.isAnonymous = function (req, res, next) {
  if (!req.isAuthenticated())
    return next();
  res.redirect('/');
}

userUtil.accessDenied = function (req, res, next) {
	res.render('access-denied', {
    messages: req.flash(),
    user: (req.user) ? req.user : null
  });
}

module.exports = userUtil;