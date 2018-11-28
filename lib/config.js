const debug = require('debug')('snyk:nodejs-runtime-agent:config');
const uuidv4 = require('uuid/v4');

const config = {};

module.exports = {
  get,
  generateConfig,
};

function get() {
  return config;
}

function generateConfig(startingConfig) {
  debug('Starting with config', startingConfig);
  validateStartingConfig(startingConfig);

  config['enable'] = true;
  config['agentId'] = uuidv4();
  config['beaconIntervalMs'] = 60 * 1000;
  config['beaconUrl'] = 'https://homebase.snyk.io/api/v1/beacon';
  config['snapshotUrl'] = `https://homebase.snyk.io/api/v1/snapshot/${startingConfig.projectId}/js`;

  if ('url' in startingConfig)  {
    config['beaconUrl'] = startingConfig['url'];
  }
  if ('beaconIntervalMs' in startingConfig) {
    config['beaconIntervalMs'] = startingConfig['beaconIntervalMs'];
  }
  if ('enable' in startingConfig) {
    config['enable'] = startingConfig['enable'];
  }
  config['projectId'] = startingConfig['projectId'];

  debug('config after applying defaults', config);
  return config;
}

function validateStartingConfig(startingConfig) {
  if (!startingConfig) {
    throw new Error('No config provided, disabling');
  }
  if (!startingConfig.projectId) {
    throw new Error('No projectId defined in configuration');
  }
}
