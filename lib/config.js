const path = require('path');
const debug = require('debug')('snyk:nodejs-runtime-agent:config');
const uuidv4 = require('uuid/v4');

module.exports = {
  initConfig,
};

function initConfig(startingConfig) {
  debug('Starting with config', startingConfig);
  validateStartingConfig(startingConfig);
  const config = {};

  config['enable'] = true;
  config['flushOnExit'] = true;
  config['agentId'] = uuidv4();
  config['beaconIntervalMs'] = 60 * 1000;
  config['snapshotIntervalMs'] = 60 * 60 * 1000;
  config['beaconUrl'] = 'https://homebase.snyk.io/api/v1/beacon';
  config['snapshotUrl'] = `https://homebase.snyk.io/api/v2/snapshot/${startingConfig.projectId}/node`;
  config['allowUnknownCA'] = false;

  config['functionPaths'] = {
    repo: {
      snapshot: path.join(__dirname, './resources/functions.repo.json'),
      date: path.join(__dirname, './resources/build-date.repo'),
    },
    bundle: {
      snapshot: path.join(__dirname, './resources/functions.bundle.json'),
      date: path.join(__dirname, './resources/build-date.bundle'),
    },
  };

  if ('url' in startingConfig)  {
    config['beaconUrl'] = startingConfig['url'];
  }

  const overrideables = [
    'snapshotUrl', 'snapshotIntervalMs', 'beaconIntervalMs',
    'enable', 'flushOnExit', 'projectId', 'functionPaths',
    'allowUnknownCA',
  ];
  for (const key of overrideables) {
    if (key in startingConfig) {
      config[key] = startingConfig[key];
    }
  }

  for (let key in config) {
    if (key !== 'initConfig') {
      this[key] = config[key];
    }
  }

  debug('config after applying defaults', config);
}

function validateStartingConfig(startingConfig) {
  if (!startingConfig) {
    throw new Error('No config provided, disabling');
  }
  if (!startingConfig.projectId) {
    throw new Error('No projectId defined in configuration');
  }
}
