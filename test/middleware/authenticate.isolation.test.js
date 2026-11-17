/* global describe, it, expect, before */
/* jshint expr: true */

require('../bootstrap/node-test');

var chai = require('chai')
  , authenticate = require('../../lib/middleware/authenticate')
  , Passport = require('../..').Passport;


describe('middleware/authenticate', function() {
  
  describe('with strategy instance passed directly, isolating state between requests', function() {
    function StatefulStrategy() {
    }
    StatefulStrategy.prototype.authenticate = function(req) {
      // state written to `this` during a previous request must not be visible
      this.attempts = (this.attempts || 0) + 1;
      this.fail('attempt ' + this.attempts);
    };
    
    var strategy = new StatefulStrategy();
    var passport = new Passport();
    
    function dispatch(cb) {
      chai.connect.use(authenticate(passport, strategy))
        .end(function(res) {
          cb(res);
        })
        .dispatch();
    }
    
    it('should not leak state written during first request into second request', function(done) {
      dispatch(function(res1) {
        expect(res1.statusCode).to.equal(401);
        expect(res1.getHeader('WWW-Authenticate')).to.deep.equal([ 'attempt 1' ]);
        
        dispatch(function(res2) {
          expect(res2.statusCode).to.equal(401);
          expect(res2.getHeader('WWW-Authenticate')).to.deep.equal([ 'attempt 1' ]);
          done();
        });
      });
    });
    
    it('should not augment the shared strategy with action functions', function() {
      expect(strategy.success).to.be.undefined;
      expect(strategy.fail).to.be.undefined;
      expect(strategy.redirect).to.be.undefined;
      expect(strategy.pass).to.be.undefined;
      expect(strategy.error).to.be.undefined;
      expect(strategy.attempts).to.be.undefined;
    });
  });
  
  describe('with strategy instance passed directly, handling concurrent requests', function() {
    function AsyncStrategy() {
    }
    AsyncStrategy.prototype.authenticate = function(req) {
      var self = this
        , user = req.headers['x-user'];
      
      // successful attempts resolve more slowly, so the failure of the
      // concurrent request is processed while this attempt is still pending
      setTimeout(function() {
        if (user) {
          self.success({ id: user });
        } else {
          self.fail('identity required');
        }
      }, user ? 20 : 5);
    };
    
    var strategy = new AsyncStrategy();
    var passport = new Passport();
    
    it('should not pollute concurrent requests with each others results', function(done) {
      var middleware = authenticate(passport, strategy, { session: false });
      var requestA, responseB, pending = 2;
      
      function finish() {
        if (--pending > 0) { return; }
        
        expect(requestA.user).to.deep.equal({ id: 'alice' });
        expect(responseB.statusCode).to.equal(401);
        expect(responseB.getHeader('WWW-Authenticate')).to.deep.equal([ 'identity required' ]);
        done();
      }
      
      chai.connect.use(middleware)
        .req(function(req) {
          requestA = req;
          req.headers['x-user'] = 'alice';
        })
        .next(function() {
          finish();
        })
        .dispatch();
      
      chai.connect.use(middleware)
        .end(function(res) {
          responseB = res;
          finish();
        })
        .dispatch();
    });
  });
  
  describe('with strategy that fails and then attempts a stale success', function() {
    function LateSuccessStrategy() {
    }
    LateSuccessStrategy.prototype.authenticate = function(req) {
      var self = this;
      
      this.fail('failure challenge');
      setTimeout(function() {
        self.success({ id: '1', username: 'jared' });
      }, 10);
    };
    
    var passport = new Passport();
    passport.use('late-success', new LateSuccessStrategy());
    
    var request, response;
    
    before(function(done) {
      chai.connect.use(authenticate(passport, 'late-success', { session: false }))
        .req(function(req) {
          request = req;
        })
        .end(function(res) {
          response = res;
          // wait for the stale success callback to fire before asserting
          setTimeout(done, 30);
        })
        .dispatch();
    });
    
    it('should respond with unauthorized status', function() {
      expect(response.statusCode).to.equal(401);
      expect(response.getHeader('WWW-Authenticate')).to.deep.equal([ 'failure challenge' ]);
    });
    
    it('should not commit user after the attempt has failed', function() {
      expect(request.user).to.be.undefined;
    });
  });
  
});
