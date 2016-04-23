'use strict';
console.log('loading login handler');

const Joi = require('joi');
const UUID = require('uuid');
const AWS = require('aws-sdk');
AWS.config.region = 'us-east-1';

const Dynamo = new AWS.DynamoDB.DocumentClient();
const Promise = require('bluebird');
const Boom = require('boom');
const Scrypt = require('scrypt-for-humans');
const JWT = require('jsonwebtoken');
const _ = require('lodash');
const secret = require('../carport-secret.json').secret;

const routeSchema = new Joi.object().keys({
  email: Joi.string().email().required(),
  password: Joi.string().min(8).required(),
});

const standardError = Boom.unauthorized('invalid userid or password');



function loginHandler(event, context) {
  return new Promise((resolve, reject) => {

    // validate inputs
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

    // first find the user, then verify password, then generate a JWT token to return to user.
    // token is necessary to call other APIs
    getUser(input)
      .then(validatePassword)
      .then(generateToken)
      .then((response) => resolve(response))
      .catch((error) => reject(error));
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
        reject(Boom.unauthorized('error reading database:' + JSON.stringify(err)));
      } else {
        if (data.Item) {
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

/**
 * Validates user password
 * @param  {object} input event
 * @return {object}       Promise that resolves if the password matches the hash,
 * or rejects if it doesn't.
 */
function validatePassword(input) {
  return new Promise((resolve, reject) => {
    try {
      Scrypt.verifyHash(input.password, input.user.hash, (err, result) => {
        if (err) {
          console.log('unable to verify hash: ' + JSON.stringify(err));
          return reject(standardError);
        } else {
          resolve(input);
        }
      })
    } catch (err) {
      console.log('exception encountered while verifying hash: ' + JSON.stringify(err));
      return reject(standardError)
    }
  })
}

/**
 * Generates a Java Web Token
 * @param  {[type]} input [description]
 * @return {[type]}       [description]
 */
function generateToken(input) {
  return new Promise((resolve, reject) => {
    var payload = {
      email: input.user.email
    }
    var options = {
      issuer: input.user.userid,
      expiresIn: '1d',
      subject: 'carport-api'
    }
    JWT.sign(payload, secret, options, (token) => {
      return resolve({
        email: input.user.email,
        token: token
      });
    });
  });
}

module.exports.route = {
  path: '/login',
  method: 'get',
  handler: loginHandler
}
