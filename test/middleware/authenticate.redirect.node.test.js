'use strict';

var test = require('node:test');
var assert = require('node:assert');

var authenticate = require('../../lib/middleware/authenticate');
var Passport = require('../..').Passport;


function SuccessStrategy() {
}
SuccessStrategy.prototype.authenticate = function() {
  this.success({ id: '1', username: 'jaredhanson' });
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
    req.logIn = function(user, options, done) {
      this.user = user;
      done();
    };

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


test('successReturnToOrRedirect uses safe path-relative returnTo', async function() {
  var passport = passportWith('success', SuccessStrategy);
  var middleware = authenticate(passport, 'success', {
    successReturnToOrRedirect: '/default'
  });
  var req = { session: { returnTo: '/account' } };

  var res = await dispatch(middleware, req);

  assert.strictEqual(res.statusCode, 302);
  assert.strictEqual(res.getHeader('Location'), '/account');
  assert.strictEqual(req.session.returnTo, undefined);
});


test('successReturnToOrRedirect falls back to configured default', async function() {
  var passport = passportWith('success', SuccessStrategy);
  var middleware = authenticate(passport, 'success', {
    successReturnToOrRedirect: '/default'
  });
  var req = { session: {} };

  var res = await dispatch(middleware, req);

  assert.strictEqual(res.getHeader('Location'), '/default');
});


test('successReturnToOrRedirect rejects scheme-relative returnTo', async function() {
  var passport = passportWith('success', SuccessStrategy);
  var middleware = authenticate(passport, 'success', {
    successReturnToOrRedirect: '/default'
  });
  var req = { session: { returnTo: '//evil.example.com/phish' } };

  var res = await dispatch(middleware, req);

  assert.strictEqual(res.getHeader('Location'), '/default');
  assert.strictEqual(req.session.returnTo, undefined);
});


test('successReturnToOrRedirect rejects backslash returnTo', async function() {
  var passport = passportWith('success', SuccessStrategy);
  var middleware = authenticate(passport, 'success', {
    successReturnToOrRedirect: '/default'
  });
  var req = { session: { returnTo: '/\\evil.example.com/phish' } };

  var res = await dispatch(middleware, req);

  assert.strictEqual(res.getHeader('Location'), '/default');
  assert.strictEqual(req.session.returnTo, undefined);
});


test('successReturnToOrRedirect rejects returnTo containing control characters', async function() {
  var passport = passportWith('success', SuccessStrategy);
  var middleware = authenticate(passport, 'success', {
    successReturnToOrRedirect: '/default'
  });
  var req = { session: { returnTo: '/account\nX' } };

  var res = await dispatch(middleware, req);

  assert.strictEqual(res.getHeader('Location'), '/default');
  assert.strictEqual(req.session.returnTo, undefined);
});


test('successReturnToOrRedirect rejects whitespace-padded scheme-relative returnTo', async function() {
  var passport = passportWith('success', SuccessStrategy);
  var middleware = authenticate(passport, 'success', {
    successReturnToOrRedirect: '/default'
  });
  var req = { session: { returnTo: '  //evil.example.com' } };

  var res = await dispatch(middleware, req);

  assert.strictEqual(res.getHeader('Location'), '/default');
  assert.strictEqual(req.session.returnTo, undefined);
});


test('successReturnToOrRedirect falls back to root when default is also unsafe', async function() {
  var passport = passportWith('success', SuccessStrategy);
  var middleware = authenticate(passport, 'success', {
    successReturnToOrRedirect: '//evil.example.com/default'
  });
  var req = { session: { returnTo: 'javascript:alert(1)' } };

  var res = await dispatch(middleware, req);

  assert.strictEqual(res.getHeader('Location'), '/');
  assert.strictEqual(req.session.returnTo, undefined);
});


test('successReturnToOrRedirect still accepts absolute http(s) URLs', async function() {
  var passport = passportWith('success', SuccessStrategy);
  var middleware = authenticate(passport, 'success', {
    successReturnToOrRedirect: 'http://www.example.com/default'
  });
  var req = { session: {} };

  var res = await dispatch(middleware, req);

  assert.strictEqual(res.getHeader('Location'), 'http://www.example.com/default');
});


test('successRedirect sanitizes dangerous values to the safe default', async function() {
  var passport = passportWith('success', SuccessStrategy);
  var middleware = authenticate(passport, 'success', {
    successRedirect: '//evil.example.com/account'
  });

  var res = await dispatch(middleware, { session: {} });

  assert.strictEqual(res.getHeader('Location'), '/');
});


test('successRedirect keeps ordinary path-relative values', async function() {
  var passport = passportWith('success', SuccessStrategy);
  var middleware = authenticate(passport, 'success', {
    successRedirect: '/account'
  });

  var res = await dispatch(middleware, { session: {} });

  assert.strictEqual(res.getHeader('Location'), '/account');
});


test('successReturnToOrRedirect ignores non-string returnTo and consumes it', async function() {
  var passport = passportWith('success', SuccessStrategy);
  var middleware = authenticate(passport, 'success', {
    successReturnToOrRedirect: '/default'
  });
  var req = { session: { returnTo: { poisoned: true } } };

  var res = await dispatch(middleware, req);

  assert.strictEqual(res.getHeader('Location'), '/default');
  assert.strictEqual(req.session.returnTo, undefined);
});
