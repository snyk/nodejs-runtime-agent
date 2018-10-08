var debug = require('debug')('snyk:nodejs-agent');

var transmitter = require('./transmitter');
var debuggerWrapper = require('./debugger-wrapper');


function start(config) {
  try {
    transmitter.start(config);
    debuggerWrapper.start();
  } catch (error) {
    debug('Generic error while starting snyk-nodejs-agent:', error);
  };
}

module.exports = start;
