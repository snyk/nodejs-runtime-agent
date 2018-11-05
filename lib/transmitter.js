const debug = require('debug')('snyk:nodejs:transmitter');
const needle = require('needle');

const DEFAULT_BEACON_BASE_URL = 'https://homebase.snyk.io';
const DEFAULT_BEACON_URL_PATH = '/api/v1/beacon';

var eventsToSend = [];

function handlePeriodicTasks({agentId,
  projectId,
  url=DEFAULT_BEACON_BASE_URL + DEFAULT_BEACON_URL_PATH,
}) {
  transmitEvents(url, projectId, agentId);
}

function transmitEvents(url, projectId, agentId) {
  let postPromise = Promise.resolve();
  debug(`agent:${agentId} transmitting ${eventsToSend.length} events to ${url} with project ID ${projectId}.`);
  postPromise = needle('post', url, {projectId, agentId, eventsToSend}, {json: true})
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
  eventsToSend = [];
  return postPromise;
}

function addEvent(event) {
  eventsToSend.push(event);
  debug(`Event added to transmission queue: ${JSON.stringify(event)}`);
}

module.exports = {handlePeriodicTasks, transmitEvents, addEvent};
