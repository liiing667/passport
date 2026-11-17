'use strict';

var test = require('node:test');
var assert = require('node:assert');

var authenticate = require('../../lib/middleware/authenticate');
var Passport = require('../..').Passport;


function FailStrategy() {
}
FailStrategy.prototype.authenticate = function() {
  this.fail();
};


function dispatch(middleware, req) {
  return new Promise(function(resolve, reject) {
    var res = {
      statusCode: 200,
      _headers: {},
      setHeader: function(name, value) { this._headers[name] = value; },
      getHeader: function(name) { return this._headers[name]; },
      end: function() { resolve(res); },
      redirect: function(url) {
        this.statusCode = 302;
        this.setHeader('Location', url);
        this.end();
      }
    };

    req = req || {};
    middleware(req, res, function(err) {
      if (err) { return reject(err); }
      resolve(res);
    });
  });
}


function passportWith(strategyName, Strategy) {
  var passport = new Passport();
  passport.use(strategyName, new Strategy());
  return passport;
}


test('failureRedirect keeps ordinary path-relative login URL', async function() {
  var passport = passportWith('fail', FailStrategy);
  var middleware = authenticate(passport, 'fail', { failureRedirect: '/login' });

  var res = await dispatch(middleware);

  assert.strictEqual(res.statusCode, 302);
  assert.strictEqual(res.getHeader('Location'), '/login');
});


test('failureRedirect rejects scheme-relative URL and uses safe default', async function() {
  var passport = passportWith('fail', FailStrategy);
  var middleware = authenticate(passport, 'fail', {
    failureRedirect: '//evil.example.com/login'
  });

  var res = await dispatch(middleware);

  assert.strictEqual(res.getHeader('Location'), '/');
});


test('failureRedirect rejects backslash URL and uses safe default', async function() {
  var passport = passportWith('fail', FailStrategy);
  var middleware = authenticate(passport, 'fail', {
    failureRedirect: '/\\evil.example.com/login'
  });

  var res = await dispatch(middleware);

  assert.strictEqual(res.getHeader('Location'), '/');
});


test('failureRedirect rejects control characters and uses safe default', async function() {
  var passport = passportWith('fail', FailStrategy);
  var middleware = authenticate(passport, 'fail', {
    failureRedirect: '/logi\rn'
  });

  var res = await dispatch(middleware);

  assert.strictEqual(res.getHeader('Location'), '/');
});


test('failureRedirect rejects javascript scheme and uses safe default', async function() {
  var passport = passportWith('fail', FailStrategy);
  var middleware = authenticate(passport, 'fail', {
    failureRedirect: 'javascript:alert(document.cookie)'
  });

  var res = await dispatch(middleware);

  assert.strictEqual(res.getHeader('Location'), '/');
});


test('failureRedirect still accepts absolute http(s) URLs', async function() {
  var passport = passportWith('fail', FailStrategy);
  var middleware = authenticate(passport, 'fail', {
    failureRedirect: 'http://www.example.com/login'
  });

  var res = await dispatch(middleware);

  assert.strictEqual(res.getHeader('Location'), 'http://www.example.com/login');
});


test('failureRedirect ignores returnTo so failures do not loop to protected entry', async function() {
  var passport = passportWith('fail', FailStrategy);
  var middleware = authenticate(passport, 'fail', { failureRedirect: '/login' });
  var req = { session: { returnTo: '//evil.example.com/admin' } };

  var res = await dispatch(middleware, req);

  assert.strictEqual(res.getHeader('Location'), '/login');
  assert.strictEqual(req.session.returnTo, '//evil.example.com/admin');
});
