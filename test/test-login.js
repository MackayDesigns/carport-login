'use strict';

'use strict;'

var Lambda = require('../index')
var Boom = require('boom')
var AWS = require('aws-sdk');

var Chai = require('chai');
var assert = Chai.assert;
var expect = Chai.expect;
var Auth = require('../index');

AWS.config.region = 'us-east-1';


beforeEach((done) => {
  done();
})

var context = {
  fail: function (error) {},
  succeed: function (response) {},
  done: function (error, response) {
    if (error) {
      this.fail(error);
    } else {
      this.succeed(response)
    }
  }
};



describe('Login:@integration', () => {
  it('should fail when invoking with an invalid request context', (done) => {
    var badContext = {
      "params": {
        "querystring": {
          "password": "garbage9",
          "email": "you@you3.com"
        }
      },
      "context": {
        "http-method": "GET",
      }
    }

    context.fail = (error) => {
      expect(error).to.exist;
      var obj = JSON.parse(error);
      expect(obj.name).to.equal('ValidationError');
      done();
    };

    Auth.handler(badContext, context);
  });

  it('should fail when invoking with an invalid email address', (done) => {
    var badEmail = {
      "params": {
        "querystring": {
          "password": "garbage8",
          "email": "you@you3.com"
        }
      },
      "context": {
        "http-method": "GET",
        "resource-path": "/login"
      }
    }
    context.fail = (error) => {
      expect(error).to.exist;
      var obj = JSON.parse(error);
      expect(obj.statusCode).to.equal(401);
      done();
    };
    context.succeed = (response) => {
      expect(response).to.not.exist;
      done();
    }
    Auth.handler(badEmail, context);
  });
  it('should fail when invoking with an invalid password', (done) => {
    var badPassword = {
      "params": {
        "querystring": {
          "password": "garbage9",
          "email": "you@you2.com"
        }
      },
      "context": {
        "http-method": "GET",
        "resource-path": "/login"
      }
    }
    context.fail = (error) => {
      expect(error).to.exist;
      var obj = JSON.parse(error);
      expect(obj.statusCode).to.equal(401);
      done();
    };
    context.succeed = (response) => {
      expect(response).to.not.exist;
      done();
    }
    Auth.handler(badPassword, context);
  });
  it('should respond with a token when invoking with a valid username and password', (done) => {
    var goodLogin = {
      "params": {
        "querystring": {
          "password": "garbage8",
          "email": "you@you2.com"
        }
      },
      "context": {
        "http-method": "GET",
        "resource-path": "/login"
      }
    };
    context.fail = (error) => {
      expect(error).to.not.exist;
      done();
    };
    context.succeed = (response) => {
      expect(response).to.exist;
      expect(response.token).to.exist;
      done();
    }
    Auth.handler(goodLogin, context);
  });
});
