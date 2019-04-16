const debug = require('debug')('snyk:nodejs:transmitter');
const needle = require('needle');

const state = require('./state');
const config = require('./config');
const systemInfo = require('./system-info').getSystemInfo();

function handlePeriodicTasks() {
  const url = config.beaconUrl;
  return transmitEvents(url, config.projectId, config.agentId);
}

function transmitEvents(url, projectId, agentId) {
  const currentState = state.get();
  let postPromise = Promise.resolve();

  debug(`agent:${agentId} transmitting ${currentState.events.length} events to ${url} with project ID ${projectId}.`);
  const body = {
    agentId,
    projectId,
    systemInfo,
    filters: currentState.filters,
    eventsToSend: currentState.events,
    loadedSources: currentState.packages,
  };

  const options = {
    json: true,
    rejectUnauthorized: !config['allowUnknownCA'],
  };

  postPromise = needle('post', url, body, options)
    .then((response) => {
      if (response && response.statusCode !== 200) {
        debug('Unexpected response for events transmission: ' +
          `${response.statusCode} : ${JSON.stringify(response.body)}`);
      } else if (response && response.statusCode === 200) {
        debug('Successfully transmitted events.');
      }
    })
    .catch((error) => {
      debug(`Error transmitting events: ${error}`);
    });
  state.clean();
  return postPromise;
}

module.exports = {
  transmitEvents,
  handlePeriodicTasks,
};
