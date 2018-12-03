const fs = require('fs');
const path = require('path');
const needle = require('needle');
const debug = require('debug')('snyk:nodejs-runtime-agent:snapshot');

const config = require('../config');

const FUNCTIONS_METATDATA_FILE = path.join(__dirname, '../../functions-to-track-runtime.json');

let lastModified = new Date(); // TODO
let vulnerabiltiesMetadata = {};

module.exports = {
  getLatest,
  loadFromLocal,
  loadFromUpstream,
  processFunctionsToInspect,
  setVulnerabiltiesMetadata,
};

function getLatest() {
  return vulnerabiltiesMetadata;
}

function loadFromLocal() {
  const appDir = path.dirname(require.main.filename);
  const appMetadataFilePath = path.join(appDir, 'functions-to-track-runtime.json');
  const exists = fs.existsSync(appMetadataFilePath);

  if (!exists) {
    vulnerabiltiesMetadata = processFunctionsToInspect(require(FUNCTIONS_METATDATA_FILE));
    return;
  }

  debug('Using app defined method.json to load vulnerabilties');
  const rawSnapshot = require(appMetadataFilePath);
  vulnerabiltiesMetadata = processFunctionsToInspect(rawSnapshot);
}

async function loadFromUpstream() {
  const url = config.snapshotUrl;
  try {
    debug(`attempting to retrieve latest snapshot from ${url}`);
    const requestOptions = {
      json: true,
      headers: {'If-Modified-Since': lastModified.toUTCString()},
    };
    const response = await needle('get', url, requestOptions);
    if (response.statusCode === 304) {
      debug('snapshot not modified');
      return;
    }
    if (response.statusCode !== 200) {
      debug(`failed retrieving latest snapshot from ${url}: ${response.statusCode}`);
      throw new Error('failed retrieving latest snapshot');
    }

    lastModified = new Date(response.headers['Last-Modified']); // TODO caps?
    const rawSnapshot = response.body;
    vulnerabiltiesMetadata = processFunctionsToInspect(rawSnapshot);
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

//TODO: fix it hack for tests
function setVulnerabiltiesMetadata(vulnMetadata) {
  vulnerabiltiesMetadata = processFunctionsToInspect(vulnMetadata);
}
