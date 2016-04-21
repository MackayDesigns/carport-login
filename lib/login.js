'use strict';
console.log('loading login handler');

const Joi = require('joi');
const UUID = require('uuid');
const AWS = require('aws-sdk');
const Dynamo = new AWS.DynamoDB.DocumentClient();
const Promise = require('bluebird');
const Boom = require('boom');
const Crypto = require('crypto');
const _ = require('lodash');

const routeSchema = new Joi.object().keys({
  email: Joi.string().email().required(),
  password: Joi.string().min(8).required(),
});

const standardError = Boom.unauthorized('invalid userid or password');

// For development/testing purposes
function loginHandler(event, context) {
  return new Promise((resolve, reject) => {

    // validate inputs
    console.log('got login request' + JSON.stringify(event));
    var input = {};

    if (event.params && event.params.querystring && event.params.querystring.email && event.params.querystring.password) {
      input.email = event.params.querystring.email
      input.password = event.params.querystring.password
      const result = Joi.validate(input, routeSchema)
      if (result.error) {
        return reject(result.error);
      }
    } else {
      return reject(Boom.badRequest('email is required in params.path'))
    }

    console.log('validated inputs');

    // first get the user, then verify password, then create token to return to user.
    // token is necessary to call other APIs

    getUser(input)
      .then(validatePassword)
      .then((response) => resolve())
      .error((error) => reject(error));
  });
}

function getUser(input) {
  return new Promise((resolve, reject) => {
    // query the user table
    var params = {
      TableName: 'users',
      Key: {
        email: input.email
      }
    };

    Dynamo.get(params, (err, data) => {
      if (err) {
        reject(Boom.unauthorizeerr);
      } else {
        if (data.Item) {
          try {
            input.hash = new Buffer(data.Item.password, 'utf8');
          } catch (error) {
            console.log('unable to retrieve password hash from user record: ' + error);
            return reject(standardError)
          }
          input.user = data.Item;
          return resolve(input);
        } else {
          console.log('user not found: ' + input.email);
          return reject(standardError);
        }
      }
    });
  });
}

function validatePassword(input) {
  console.log('validating password for: ' + JSON.stringify(input.email))
  return new Promise((resolve, reject) => {
    var combined = input.hash;
    var saltBytes = combined.readUInt32BE(0);
    var hashBytes = combined.length - saltBytes - 8;
    var iterations = combined.readUInt32BE(4);
    var salt = combined.slice(8, saltBytes + 8);
    var hash = combined.toString('binary', saltBytes + 8);
    console.log('comparing hashed password. iterations = ' + iterations + ', saltBytes = ' + saltBytes.toString('utf8') + ', salt = ' + salt.toString('utf8'));
    Crypto.pbkdf2(input.password, salt, iterations, hashBytes, (err, verify) => {
      if (err) {
        console.log('error validating password: ' + JSON.stringify(err));
        reject(standard);
      } else {
        console.log('returned from pbkdf2');
        var goodPassword = verify.toString('binary' === hash)
        if (goodPassword) {
          resolve(input);
        } else {
          reject(standardError);
        }
      }
    })
  })
}

module.exports.route = {
  path: '/login',
  method: 'get',
  handler: loginHandler
}