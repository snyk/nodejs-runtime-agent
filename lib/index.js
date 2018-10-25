const uuidv4 = require('uuid/v4');
const debug = require('debug')('snyk:nodejs-runtime-agent');

const transmitter = require('./transmitter');
const debuggerWrapper = require('./debugger-wrapper');


function start(config) {
  try {
    debug('Starting with config', config);

    if (!config) {
      throw new Error('No config provided, disabling');
    }

    if (config.enable === undefined) {
      config.enable = true; // enable by default
    }

    if (!config.enable) {
      debug('Runtime agent is disabled');
      return;
    }

    config.agentId = config.agentId || uuidv4();
    transmitter.start(config);
    debuggerWrapper.start();
  } catch (error) {
    // using console.log here as this is a one-time message
    // and will be used as a lead to enable debug mode
    console.log('Error while starting Snyk runtime agent', error);
  };
}

module.exports = start;
