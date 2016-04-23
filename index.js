'use strict';
console.log('Loading handler function');

const Lambda = require('lambda-time');
const Router = new Lambda();

module.exports = {};

Router.register(require('./lib/login').route);

module.exports.handler = function (event, context) {
  Router.route(event, context)
    .then((response) => {
      context.done(null, response);
    })
    .catch((error) => {
      context.done(JSON.stringify(error), null);
    })
}
