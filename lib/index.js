const uuidv4 = require('uuid/v4');
const debug = require('debug')('snyk:nodejs-runtime-agent');

const transmitter = require('./transmitter');
const debuggerWrapper = require('./debugger-wrapper');

const DEFAULT_BEACON_INTERVAL_MS = 60 * 1000;

function start(config) {
  try {
    debug('Starting with config', config);
    validateConfig(config);
    config = applyDefaultConfig(config);
    debug('config after applying defaults', config);

    if (!config.enable) {
      debug('Runtime agent is disabled');
      return;
    }

    debuggerWrapper.init();

    setInterval(() => {
      debuggerWrapper.handlePeriodicTasks();
      transmitter.handlePeriodicTasks(config);
    }, config.beaconIntervalMs).unref();
  } catch (error) {
    // using console.log here as this is a one-time message
    // and will be used as a lead to enable debug mode
    console.log('Error while starting Snyk runtime agent', error);
  };
}

function validateConfig(config) {
  if (!config) {
    throw new Error('No config provided, disabling');
  }
  if (!config.projectId) {
    throw new Error('No projectId defined in configuration');
  }
}

function applyDefaultConfig(config) {
  return {
    ...config,
    beaconIntervalMs: config.beaconIntervalMs || DEFAULT_BEACON_INTERVAL_MS,
    enable: (config.enable === undefined) ? true : config.enable,
    agentId: config.agentId || uuidv4(),
  };
}

module.exports = start;
