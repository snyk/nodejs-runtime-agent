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

    applyDefaultConfig(config);

    if (!config.enable) {
      debug('Runtime agent is disabled');
      return;
    }

    transmitter.start(config);
    debuggerWrapper.start(config);
  } catch (error) {
    // using console.log here as this is a one-time message
    // and will be used as a lead to enable debug mode
    console.log('Error while starting Snyk runtime agent', error);
  };
}

function applyDefaultConfig(config) {
  if (config.enable === undefined) {
    config.enable = true; // enable by default
  }

  config.agentId = config.agentId || uuidv4();
  config.snoozeMethodMs = config.snoozeMethodMs || process.env.SNYK_SNOOZE_METHOD_MS || 2 * 60 * 60 * 1000;

  debug('config after applying defaults', config);
}

module.exports = start;
