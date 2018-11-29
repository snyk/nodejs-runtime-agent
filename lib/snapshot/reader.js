const fs = require('fs');
const path = require('path');
const needle = require('needle');
const debug = require('debug')('snyk:nodejs-runtime-agent:snapshot');

const FUNCTIONS_METATDATA_FILE = path.join(__dirname, '../../functions-to-track-runtime.json');

module.exports = {
  getLatest,
  processFunctionsToInspect,
};

function getLatest(local) {
  let rawSnapshot;
  if (local) {
    debug('loading local snapshot');
    rawSnapshot = fromLocal();
  }

  return processFunctionsToInspect(rawSnapshot);
}

async function fromUpstream(projectId) {
  // TODO AMIR: refactor config
  const SNAPSHOT_BASE_URL = 'https://homebase.snyk.io';
  const SNAPSHOT_URL_PATH = `/api/v1/snapshot/${projectId}/js`;
  const url = SNAPSHOT_BASE_URL + SNAPSHOT_URL_PATH;
  try {
    return await needle('get', url);
  } catch (error) {
    debug(`failed retrieving latest snapshot from ${url}: ${error}`);
    return {};
  }
}

function fromLocal() {
  const appDir = path.dirname(require.main.filename);
  const appMetadataFilePath = path.join(appDir, 'functions-to-track-runtime.json');
  const exists = fs.existsSync(appMetadataFilePath);

  if (!exists) {
    return require(FUNCTIONS_METATDATA_FILE);
  }

  debug('Using app defined method.json to load vulnerabilties');
  return require(appMetadataFilePath);
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
