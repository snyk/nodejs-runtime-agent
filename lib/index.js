var debug = require('debug')('snyk:nodejs-runtime-agent');
const uuidv4 = require('uuid/v4');

var transmitter = require('./transmitter');
var debuggerWrapper = require('./debugger-wrapper');

const runtimeAgentId = uuidv4();

function start(config) {
  try {
    transmitter.start({runtimeAgentId, ...config});
    debuggerWrapper.start();
  } catch (error) {
    debug('Generic error while starting snyk-nodejs-runtime-agent:', error);
  };
}

module.exports = start;
