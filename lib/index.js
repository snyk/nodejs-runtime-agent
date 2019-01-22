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

    if (config.flushOnExit) {
      setFlushOnExit();
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

    const snapshotInterval = setInterval(() => {
      try {
        snapshot.refresh()
          .then(() => {
            try {
              debuggerWrapper.refreshInstrumentation();
            } catch (err) {
              debug(`failed re-instrumenting the agent ${err}, possibly due to bad snapshot.`);
              debug('will retry with the next snapshot');
            }
          })
          .catch((err) => {
            debug(`failed retrieving new snapshot ${err}, will retry again later`);
          });
      } catch (error) {
        try {
          stopIntervals();
          console.log('Error in Snyk runtime agent, please contact runtime@snyk.io', error);
        } catch (err) {}
      }
    }, config.snapshotIntervalMs).unref();
    intervals.push(snapshotInterval);
  } catch (error) {
    // using console.log here as this is a one-time message
    // and will be used as a lead to enable debug mode
    console.log('Error while starting Snyk runtime agent, please contact runtime@snyk.io', error);
  };
}

function setFlushOnExit() {
  let flushedOnce = false;
  function handleBeforeExit() {
    if (flushedOnce) {
      return;
    }

    debug('flushing last beacons before exiting');
    transmitter.handlePeriodicTasks()
      .then(() => {
        flushedOnce = true;
      })
      .catch(() => {
        flushedOnce = true;
      });
  }

  process.on('beforeExit', handleBeforeExit);
}

function stopIntervals() {
  intervals.forEach((currentInterval) => {
    clearInterval(currentInterval);
  });
}

module.exports = start;
