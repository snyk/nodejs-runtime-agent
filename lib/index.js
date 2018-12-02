const debug = require('debug')('snyk:nodejs-runtime-agent');

const config = require('./config');
const snapshot = require('./snapshot');
const transmitter = require('./transmitter');
const debuggerWrapper = require('./debugger-wrapper');

const intervals = [];

function start(startingConfig) {
  try {
    debug('If you have any issues during this beta, please contact runtime@snyk.io');
    config.initConfig(startingConfig);

    if (!config.enable) {
      debug('Runtime agent is disabled');
      return;
    }

    snapshot.init();
    debuggerWrapper.init();

    const beaconInterval = setInterval(() => {
      try {
        debuggerWrapper.resumeSnoozedBreakpoints();
        transmitter.handlePeriodicTasks();
      } catch (error) {
        try {
          stopIntervals();
          console.log('Error in Snyk runtime agent, please contact runtime@snyk.io', error);
        } catch (err) {}
      }
    }, config.beaconIntervalMs).unref();
    intervals.push(beaconInterval);
  } catch (error) {
    // using console.log here as this is a one-time message
    // and will be used as a lead to enable debug mode
    console.log('Error while starting Snyk runtime agent, please contact runtime@snyk.io', error);
  };
}

function stopIntervals() {
  intervals.forEach((currentInterval) => {
    clearInterval(currentInterval);
  });
}

module.exports = start;
