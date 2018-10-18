var debug = require('debug')('snyk:nodejs:transmitter');
var needle = require('needle');

const DEFAULT_BEACON_BASE_URL = 'https://homebase.snyk.io';
const DEFAULT_BEACON_URL_PATH = '/api/v1/beacon';
const DEFAULT_BEACON_INTERVAL_MS = 60 * 1000;
const DEFAULT_HEALTH_CHECK_INTERVAL_MS = 30 * 1000;

var eventsToSend = [];

function start({
  projectId,
  url=DEFAULT_BEACON_BASE_URL + DEFAULT_BEACON_URL_PATH,
  beaconIntervalMs=DEFAULT_BEACON_INTERVAL_MS,
  healthCheckIntervalMs=DEFAULT_HEALTH_CHECK_INTERVAL_MS,
}) {
  if (!projectId) {
    throw new Error('No projectId defined in configuration');
  }

  setInterval(() => {
    transmitEvents(url, projectId);
  }, beaconIntervalMs).unref();

  setInterval(() => {
    transmitHealthCheck(url, projectId);
  }, healthCheckIntervalMs).unref();
}

function logResponse(logContext, response) {
  if (!response) {
    return;
  }

  if (response.statusCode !== 200) {
    debug(`Unexpected response for ${logContext} transmission: ` +
      `${response.statusCode} : ${JSON.stringify(response.body)}`);
    return;
  }

  debug(`Successfully transmitted ${logContext}.`);
}

function logError(logContext, error) {
  debug(`Error transmitting ${logContext}: ${error}`);
}

function transmitEvents(url, projectId) {
  if (!eventsToSend.length) {
    return Promise.resolve();
  }

  const logContext = 'events';

  debug(`Transmitting ${eventsToSend.length} events.`);
  const promise = needle('post', url, {projectId, eventsToSend}, {json: true})
    .then((response) => {
      logResponse(logContext, response);
    })
    .catch((error) => {
      logError(logContext, error);
    });
  eventsToSend = [];
  return promise;
}

function transmitHealthCheck(url, projectId) {
  const logContext = 'health-check';
  const healthCheck = true;
  return needle('post', url, {projectId, healthCheck}, {json: true})
    .then((response) => {
      logResponse(logContext, response);
    })
    .catch((error) => {
      logError(logContext, error);
    });
}

function addEvent(event) {
  eventsToSend.push(event);
  debug(`Event added to transmission queue: ${JSON.stringify(event)}`);
}

module.exports = {start, transmitEvents, addEvent};
