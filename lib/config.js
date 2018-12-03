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
  config['agentId'] = uuidv4();
  config['beaconIntervalMs'] = 60 * 1000;
  config['snapshotIntervalMs'] = 60 * 60 * 1000;
  config['beaconUrl'] = 'https://homebase.snyk.io/api/v1/beacon';
  config['snapshotUrl'] = `https://homebase.snyk.io/api/v1/snapshot/${startingConfig.projectId}/node`;

  if ('url' in startingConfig)  {
    config['beaconUrl'] = startingConfig['url'];
  }

  for (const key of ['snapshotUrl', 'snapshotIntervalMs', 'beaconIntervalMs', 'enable', 'projectId']) {
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
