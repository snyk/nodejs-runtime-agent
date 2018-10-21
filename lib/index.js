const uuidv4 = require('uuid/v4');
const debug = require('debug')('snyk:nodejs-runtime-agent');

const transmitter = require('./transmitter');
const debuggerWrapper = require('./debugger-wrapper');


function start(config) {
  try {
    const agentId = uuidv4();
    transmitter.start({...config, agentId});
    debuggerWrapper.start();
  } catch (error) {
    debug('Generic error while starting snyk-nodejs-runtime-agent:', error);
  };
}

module.exports = start;
