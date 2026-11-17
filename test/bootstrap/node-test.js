/**
 * Compatibility shim that allows the mocha-style tests in this repository to
 * also run under Node's built-in test runner (`node --test`).
 *
 * Test files require this module before anything else:
 *
 *     require('./bootstrap/node-test');
 *
 * When the tests are executed by mocha, the `describe`/`it`/`expect` globals
 * already exist and this module does nothing.  Under `node --test`, it maps
 * the mocha-style globals onto `node:test` - including support for
 * callback-style (`done`) hooks and tests - and sets up chai exactly like
 * `test/bootstrap/node.js` does for mocha.
 */

if (typeof describe === 'undefined') {
  var nt = require('node:test');

  // Adapt a mocha-style function to `node:test`.  Functions that declare a
  // `done` callback parameter are wrapped in a promise; all other functions
  // are passed through untouched.
  function adapt(fn) {
    if (typeof fn != 'function') { return fn; }
    if (fn.length > 0) {
      return function() {
        var self = this;
        return new Promise(function(resolve, reject) {
          fn.call(self, function(err) {
            if (err) { return reject(err); }
            resolve();
          });
        });
      };
    }
    return fn;
  }

  global.describe = function(name, fn) { return nt.describe(name, fn); };
  global.it = function(name, fn) { return nt.it(name, adapt(fn)); };
  global.before = function(fn) { return nt.before(adapt(fn)); };
  global.after = function(fn) { return nt.after(adapt(fn)); };
  global.beforeEach = function(fn) { return nt.beforeEach(adapt(fn)); };
  global.afterEach = function(fn) { return nt.afterEach(adapt(fn)); };
}

if (typeof expect === 'undefined') {
  var chai = require('chai');

  chai.use(require('chai-connect-middleware'));
  chai.use(require('chai-passport-strategy'));

  global.$require = require('proxyquire');
  global.expect = chai.expect;
}
