const fs = require('fs');
const path = require('path');
const needle = require('needle');
const debug = require('debug')('snyk:nodejs-runtime-agent:snapshot');

const config = require('../config');

const FUNCTIONS_METATDATA_FILE = path.join(__dirname, '../../functions-to-track-runtime.json');

module.exports = {
  fromLocal,
  fromUpstream,
  processFunctionsToInspect,
};

function fromLocal() {
  const appDir = path.dirname(require.main.filename);
  const appMetadataFilePath = path.join(appDir, 'functions-to-track-runtime.json');
  const exists = fs.existsSync(appMetadataFilePath);

  if (!exists) {
    return processFunctionsToInspect(require(FUNCTIONS_METATDATA_FILE));
  }

  debug('Using app defined method.json to load vulnerabilties');
  const rawSnapshot = require(appMetadataFilePath);
  return processFunctionsToInspect(rawSnapshot);
}

async function fromUpstream() {
  const url = config.snapshotUrl;
  try {
    debug(`attempting to retrieve latest snapshot from ${url}`);
    const response = await needle('get', url, {json: true});
    // TODO handle ok response without a newer snapshot
    if (response.statusCode !== 200) {
      debug(`failed retrieving latest snapshot from ${url}: ${response.statusCode}`);
      throw new Error('failed retrieving latest snapshot');
    }

    const rawSnapshot = response.body;
    return processFunctionsToInspect(rawSnapshot);
  } catch (error) {
    debug(`failed retrieving latest snapshot from ${url}: ${error}`);
    throw new Error('failed retrieving latest snapshot');
  }
}

function processFunctionsToInspect(functions) {
  const processedFunctions = {};
  functions.forEach(currentFunction => {
    try {
      if (!(currentFunction.packageName in processedFunctions)) {
        processedFunctions[currentFunction.packageName] = {};
      }
      if (!(currentFunction.methodId.filePath in processedFunctions[currentFunction.packageName])) {
        processedFunctions[currentFunction.packageName][currentFunction.methodId.filePath] = [];
      }
      processedFunctions[currentFunction.packageName][currentFunction.methodId.filePath].push({
        name: currentFunction.methodId.methodName,
        semver: currentFunction.version,
      });
    } catch (err) {
      debug(`Failed inspecting ${currentFunction}:`, err);
    }
  });
  return processedFunctions;
}
