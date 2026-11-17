/* global expect */

var test = require('node:test');
var describe = test.describe;
var it = test.it;
var before = test.before;

var chai = require('chai');
chai.use(require('chai-connect-middleware'));
var expect = chai.expect;

var authenticate = require('../../lib/middleware/authenticate');
var Passport = require('../..').Passport;

// Drives the middleware through chai-connect-middleware and resolves once the
// request is handled.  `setup(builder, out)` receives the chai builder (to
// attach `.req`/`.res` hooks) and a shared `out` object; after dispatch the
// same `out` object carries `res`, `err` and any custom-callback arguments.
// node:test hooks have no mocha-style `done`, so the dispatch is promisified.
function run(middleware, setup, extension) {
  return new Promise(function(resolve, reject) {
    var out = { res: undefined, err: undefined, callback: undefined };
    var builder = extension
      ? chai.connect.use(extension, middleware)
      : chai.connect.use(middleware);
    var settled = false;

    function finish() {
      if (settled) { return; }
      settled = true;
      resolve(out);
    }

    builder
      .res(function(res) { out.res = res; })
      .end(function() { finish(); })
      .next(function(err) { out.err = err; finish(); });

    setup(builder, out);
    try {
      builder.dispatch();
    } catch (e) {
      reject(e);
    }
  });
}


describe('middleware/authenticate', function() {

  // ---------------------------------------------------------------------------
  // Category 3: system exceptions.
  //
  // A strategy that calls `this.error(err)` reports that authentication could
  // not be performed at all.  The exception is handed to the application's
  // error-handling chain via `next(err)`; the middleware itself never
  // serializes the error (and thus never echoes its internal message) back to
  // the user agent.
  // ---------------------------------------------------------------------------

  describe('error', function() {
    function Strategy() {
    }
    Strategy.prototype.authenticate = function() {
      this.error(new Error('something is wrong'));
    };

    var passport = new Passport();
    passport.use('error', new Strategy());

    var request, out;

    before(function() {
      return run(authenticate(passport, 'error'), function(builder) {
        builder.req(function(req) { request = req; });
      }).then(function(result) { out = result; });
    });

    it('should pass the system exception to next', function() {
      expect(out.err).to.be.an.instanceOf(Error);
      expect(out.err.message).to.equal('something is wrong');
    });

    it('should not set user', function() {
      expect(request.user).to.be.undefined;
    });

    it('should not write a public response body', function() {
      expect(out.res.body).to.be.undefined;
    });
  });

  describe('system exception does not leak internal details into a response', function() {
    function Strategy() {
    }
    Strategy.prototype.authenticate = function() {
      this.error(new Error('database credentials are root:hunter2'));
    };

    var passport = new Passport();
    passport.use('error', new Strategy());

    var out;

    before(function() {
      return run(authenticate(passport, 'error', { failureFlash: true }), function(builder) {
        builder.req(function(req) {
          req.flash = function() {
            throw new Error('flash must not be used for system exceptions');
          };
        });
      }).then(function(result) { out = result; });
    });

    it('should delegate the exception rather than answering the user agent', function() {
      expect(out.err).to.be.an.instanceOf(Error);
      expect(out.res.body).to.be.undefined;
      expect(out.res.getHeader('WWW-Authenticate')).to.be.undefined;
    });
  });

  // ---------------------------------------------------------------------------
  // Category 2: strategy faults reported through the failure action.
  //
  // A strategy may hand an `Error` object to `this.fail()`.  That means the
  // strategy could not make a decision (a policy fault), not that the
  // credentials were rejected.  The internal message must never appear in any
  // public channel (flash, session messages, WWW-Authenticate header or body).
  // ---------------------------------------------------------------------------

  describe('strategy fault passed to fail', function() {
    function Strategy() {
    }
    Strategy.prototype.authenticate = function() {
      this.fail(new Error('user directory unreachable'));
    };

    var passport = new Passport();
    passport.use('fault', new Strategy());

    var request, out;

    before(function() {
      return run(authenticate(passport, 'fault', {
          failureFlash: true,
          failureMessage: true,
          failureRedirect: 'http://www.example.com/login'
        }), function(builder) {
        builder.req(function(req) {
          request = req;
          req.session = {};
          req.flash = function(type, msg) {
            this.message = { type: type, msg: msg };
          };
        });
      }, 'express').then(function(result) { out = result; });
    });

    it('should not set user', function() {
      expect(request.user).to.be.undefined;
    });

    it('should not flash the internal error message', function() {
      expect(request.message).to.be.undefined;
    });

    it('should not store the internal error message in the session', function() {
      expect(request.session.messages).to.be.undefined;
    });

    it('should redirect without exposing the fault', function() {
      expect(out.res.statusCode).to.equal(302);
      expect(out.res.getHeader('Location')).to.equal('http://www.example.com/login');
    });
  });

  describe('strategy fault without redirect', function() {
    function Strategy() {
    }
    Strategy.prototype.authenticate = function() {
      this.fail(new Error('secret backend detail'));
    };

    var passport = new Passport();
    passport.use('fault', new Strategy());

    var out;

    before(function() {
      return run(authenticate(passport, 'fault'), function() {}).then(function(result) {
        out = result;
      });
    });

    it('should respond with a generic unauthorized status', function() {
      expect(out.res.statusCode).to.equal(401);
      expect(out.res.body).to.equal('Unauthorized');
    });

    it('should not put the internal message in the authenticate header', function() {
      expect(out.res.getHeader('WWW-Authenticate')).to.be.undefined;
    });
  });

  describe('strategy fault classification delegated to application policy', function() {
    function Strategy() {
    }
    Strategy.prototype.authenticate = function() {
      this.fail(new Error('ldap server down'));
    };

    var passport = new Passport();
    passport.use('fault', new Strategy());

    var out;

    before(function() {
      return run(authenticate(passport, 'fault', { failWithError: true }), function() {})
        .then(function(result) { out = result; });
    });

    it('should route the fault through the error chain', function() {
      expect(out.err).to.be.an.instanceOf(Error);
      expect(out.err.constructor.name).to.equal('AuthenticationError');
    });

    it('should not disclose the internal message', function() {
      expect(out.err.message).to.equal('Unauthorized');
      expect(out.err.message).to.not.equal('ldap server down');
      expect(out.err.status).to.equal(401);
    });

    it('should not write a response body', function() {
      expect(out.res.body).to.be.undefined;
    });
  });

  // ---------------------------------------------------------------------------
  // Category 1: authentication rejections (ordinary `fail()` calls) stay in the
  // public failure channel and remain fully supported.
  // ---------------------------------------------------------------------------

  describe('authentication rejection remains a public failure', function() {
    function Strategy() {
    }
    Strategy.prototype.authenticate = function() {
      this.fail({ message: 'Invalid password' }, 401);
    };

    var passport = new Passport();
    passport.use('reject', new Strategy());

    var request, out;

    before(function() {
      return run(authenticate(passport, 'reject', {
          failureFlash: true,
          failureMessage: true
        }), function(builder) {
        builder.req(function(req) {
          request = req;
          req.session = {};
          req.flash = function(type, msg) {
            this.message = { type: type, msg: msg };
          };
        });
      }).then(function(result) { out = result; });
    });

    it('should flash the public challenge message', function() {
      expect(request.message.type).to.equal('error');
      expect(request.message.msg).to.equal('Invalid password');
    });

    it('should store the public challenge message in the session', function() {
      expect(request.session.messages).to.have.length(1);
      expect(request.session.messages[0]).to.equal('Invalid password');
    });

    it('should respond unauthorized', function() {
      expect(out.res.statusCode).to.equal(401);
      expect(out.res.body).to.equal('Unauthorized');
    });
  });

  // ---------------------------------------------------------------------------
  // Multi-strategy chains: an earlier internal fault must not override a later
  // displayable challenge, and internal details must never be rendered.
  // ---------------------------------------------------------------------------

  describe('multiple strategies where an earlier fault precedes a public challenge', function() {
    function FaultyStrategy() {
    }
    FaultyStrategy.prototype.authenticate = function() {
      this.fail(new Error('internal outage'));
    };

    function BasicStrategy() {
    }
    BasicStrategy.prototype.authenticate = function() {
      this.fail('BASIC challenge');
    };

    var passport = new Passport();
    passport.use('faulty', new FaultyStrategy());
    passport.use('basic', new BasicStrategy());

    var request, out;

    before(function() {
      return run(authenticate(passport, ['faulty', 'basic'], {
          failureFlash: true,
          failureMessage: true
        }), function(builder) {
        builder.req(function(req) {
          request = req;
          req.session = {};
          req.flash = function(type, msg) {
            this.message = { type: type, msg: msg };
          };
        });
      }).then(function(result) { out = result; });
    });

    it('should flash the later public challenge, not the internal fault', function() {
      expect(request.message).to.not.be.undefined;
      expect(request.message.msg).to.equal('BASIC challenge');
    });

    it('should keep the internal message out of the session', function() {
      expect(request.session.messages).to.have.length(1);
      expect(request.session.messages[0]).to.equal('BASIC challenge');
    });

    it('should respond with the public challenge header', function() {
      expect(out.res.statusCode).to.equal(401);
      expect(out.res.getHeader('WWW-Authenticate')).to.deep.equal(['BASIC challenge']);
      expect(out.res.body).to.equal('Unauthorized');
    });
  });

  describe('multiple strategies where every result is a fault', function() {
    function StrategyA() {
    }
    StrategyA.prototype.authenticate = function() {
      this.fail(new Error('first secret'));
    };

    function StrategyB() {
    }
    StrategyB.prototype.authenticate = function() {
      this.fail(new Error('second secret'));
    };

    var passport = new Passport();
    passport.use('a', new StrategyA());
    passport.use('b', new StrategyB());

    var request, out;

    before(function() {
      return run(authenticate(passport, ['a', 'b'], { failureFlash: true }), function(builder) {
        builder.req(function(req) {
          request = req;
          req.flash = function(type, msg) {
            this.message = { type: type, msg: msg };
          };
        });
      }).then(function(result) { out = result; });
    });

    it('should not flash any internal message', function() {
      expect(request.message).to.be.undefined;
    });

    it('should respond generically without authenticate headers', function() {
      expect(out.res.statusCode).to.equal(401);
      expect(out.res.getHeader('WWW-Authenticate')).to.be.undefined;
      expect(out.res.body).to.equal('Unauthorized');
    });
  });

  // ---------------------------------------------------------------------------
  // Custom callbacks keep their original invocation order and signature, even
  // when an `Error` is supplied through the failure action.
  // ---------------------------------------------------------------------------

  describe('custom callback receives failures in the original order', function() {
    function FaultyStrategy() {
    }
    FaultyStrategy.prototype.authenticate = function() {
      this.fail(new Error('first fault detail'));
    };

    function RejectStrategy() {
    }
    RejectStrategy.prototype.authenticate = function() {
      this.fail('BASIC challenge');
    };

    var passport = new Passport();
    passport.use('faulty', new FaultyStrategy());
    passport.use('reject', new RejectStrategy());

    var request, args, order;

    before(function() {
      order = [];
      return new Promise(function(resolve) {
        var builder = chai.connect.use(authenticate(passport, ['faulty', 'reject'], function() {
          args = Array.prototype.slice.call(arguments);
          order.push('callback');
          resolve();
        }));
        builder.req(function() { order.push('dispatch'); });
        builder.dispatch();
      });
    });

    it('should not error', function() {
      expect(args[0]).to.be.null;
    });

    it('should pass false as the user', function() {
      expect(args[1]).to.equal(false);
    });

    it('should preserve chain order for challenges', function() {
      var challenges = args[2];
      expect(challenges).to.have.length(2);
      expect(challenges[0]).to.be.an.instanceOf(Error);
      expect(challenges[0].message).to.equal('first fault detail');
      expect(challenges[1]).to.equal('BASIC challenge');
    });

    it('should align statuses with challenges', function() {
      var statuses = args[3];
      expect(statuses).to.have.length(2);
      expect(statuses[0]).to.be.undefined;
      expect(statuses[1]).to.be.undefined;
    });

    it('should invoke the callback after dispatch began', function() {
      expect(order).to.deep.equal(['dispatch', 'callback']);
    });
  });

  describe('custom callback still receives a system exception first', function() {
    function Strategy() {
    }
    Strategy.prototype.authenticate = function() {
      this.error(new Error('something is wrong'));
    };

    var passport = new Passport();
    passport.use('error', new Strategy());

    var request, args;

    before(function() {
      return new Promise(function(resolve) {
        function callback() {
          args = Array.prototype.slice.call(arguments);
          resolve();
        }
        var builder = chai.connect.use(authenticate(passport, 'error', callback));
        builder.req(function(req) { request = req; });
        builder.dispatch();
      });
    });

    it('should pass error to callback', function() {
      expect(args[0]).to.be.an.instanceOf(Error);
      expect(args[0].message).to.equal('something is wrong');
    });

    it('should not set user on request', function() {
      expect(request.user).to.be.undefined;
      expect(args[1]).to.be.undefined;
    });
  });

});
