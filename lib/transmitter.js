const debug = require('debug')('snyk:nodejs:transmitter');
const needle = require('needle');

const config = require('./config').get();
const systemInfo = require('./system-info').getSystemInfo();

const eventsToSend = [];

function handlePeriodicTasks() {
  const url = config.beaconUrl;
  transmitEvents(url, config.projectId, config.agentId);
}

function transmitEvents(url, projectId, agentId) {
  let postPromise = Promise.resolve();
  debug(`agent:${agentId} transmitting ${eventsToSend.length} events to ${url} with project ID ${projectId}.`);
  const body = {projectId, agentId, eventsToSend, systemInfo, filters: []};
  postPromise = needle('post', url, body, {json: true})
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
  clearEvents();
  return postPromise;
}

function clearEvents() {
  eventsToSend.length = 0;
}

function addEvent(event) {
  event.timestamp = (new Date()).toISOString();
  eventsToSend.push(event);
  debug(`Event added to transmission queue: ${JSON.stringify(event)}`);
}

module.exports = {handlePeriodicTasks, transmitEvents, addEvent};
