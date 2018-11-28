const debug = require('debug')('snyk:nodejs-runtime-agent');

const configModule = require('./config');
const snapshot = require('./snapshot');
const transmitter = require('./transmitter');
const debuggerWrapper = require('./debugger-wrapper');

function start(config) {
  try {
    debug('If you have any issues during this beta, please contact runtime@snyk.io');
    config = configModule.generateConfig(config);

    if (!config.enable) {
      debug('Runtime agent is disabled');
      return;
    }

    snapshot.init();
    debuggerWrapper.init();

    const periodicInterval = setInterval(() => {
      try {
        debuggerWrapper.handlePeriodicTasks();
        transmitter.handlePeriodicTasks();
      } catch (error) {
        try {
          clearInterval(periodicInterval);
          console.log('Error in Snyk runtime agent, please contact runtime@snyk.io', error);
        } catch (err) {}
      }
    }, config.beaconIntervalMs).unref();
  } catch (error) {
    // using console.log here as this is a one-time message
    // and will be used as a lead to enable debug mode
    console.log('Error while starting Snyk runtime agent, please contact runtime@snyk.io', error);
  };
}

module.exports = start;
