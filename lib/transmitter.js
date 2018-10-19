var debug = require('debug')('snyk:nodejs:transmitter');
var needle = require('needle');
const os = require('os');
const uuidv4 = require('uuid/v4');

const logHelper = require('./logHelper');

const DEFAULT_BEACON_BASE_URL = 'https://homebase.snyk.io';
const DEFAULT_BEACON_URL_PATH = '/api/v1/beacon';
const DEFAULT_BEACON_INTERVAL_MS = 60 * 1000;
const DEFAULT_HEALTH_CHECK_INTERVAL_MS = 30 * 1000;

const runtimeAgentId = uuidv4();

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

function buildCurrentHeader() {
  return {
    timestamp: new Date().toISOString(),
    systemInfo: {
      hostname: os.hostname(),
      node: {
        title: process.title,
        versions: process.versions,
        pid: process.pid,
      },
    },
    correlationId: uuidv4(),
    runtimeAgentId,
  };
}

function transmitEvents(url, projectId) {
  if (!eventsToSend.length) {
    return Promise.resolve();
  }

  const header = buildCurrentHeader();
  const logContext = 'events';

  debug(`Transmitting ${eventsToSend.length} events.`);
  const beacon = {projectId, eventsToSend, ...header};
  const promise = needle('post', url, beacon, {json: true})
    .then((response) => {
      logHelper.response(debug, logContext, response);
    })
    .catch((error) => {
      logHelper.error(debug, logContext, error);
    });
  eventsToSend = [];
  return promise;
}

function transmitHealthCheck(url, projectId) {
  const header = buildCurrentHeader();
  const logContext = 'health-check';

  const healthCheck = true;
  const beacon = {projectId, healthCheck, ...header};
  return needle('post', url, beacon, {json: true})
    .then((response) => {
      logHelper.response(debug, logContext, response);
    })
    .catch((error) => {
      logHelper.error(debug, logContext, error);
    });
}

function addEvent(event) {
  eventsToSend.push(event);
  debug(`Event added to transmission queue: ${JSON.stringify(event)}`);
}

module.exports = {start, transmitEvents, transmitHealthCheck, addEvent};
