var debug = require('debug')('snyk:nodejs:transmitter');
var needle = require('needle');

const DEFAULT_BEACON_BASE_URL = 'https://homebase.snyk.io';
const DEFAULT_BEACON_URL_PATH = '/api/v1/beacon';
const DEFAULT_BEACON_INTERVAL_MS = 60 * 1000;

var eventsToSend = [];

function start({
  projectId,
  url=DEFAULT_BEACON_BASE_URL + DEFAULT_BEACON_URL_PATH,
  beaconIntervalMs=DEFAULT_BEACON_INTERVAL_MS,
}) {
  if (!projectId) {
    throw new Error('No projectId defined in configuration');
  }

  setInterval(() => {
    transmitEvents(url, projectId);
  }, beaconIntervalMs).unref();
}

function transmitEvents(url, projectId) {
  let postPromise = Promise.resolve();
  if (eventsToSend.length) {
    debug(`Transmitting ${eventsToSend.length} events to ${url} with project ID ${projectId}.`);
    postPromise = needle('post', url, {projectId, eventsToSend}, {json: true})
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
  }
  return postPromise;
}

function addEvent(event) {
  eventsToSend.push(event);
  debug(`Event added to transmission queue: ${JSON.stringify(event)}`);
}

module.exports = {start, transmitEvents, addEvent};
