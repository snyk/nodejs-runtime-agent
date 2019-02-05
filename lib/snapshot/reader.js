const fs = require('fs');
const needle = require('needle');
const debug = require('debug')('snyk:nodejs-runtime-agent:snapshot');

const config = require('../config');

let lastModified;
let vulnerabilitiesMetadata = {};

module.exports = {
  getLatest,
  loadFromLocal,
  loadFromUpstream,
  setVulnerabilitiesMetadata,
};

function getLatest() {
  return vulnerabilitiesMetadata;
}

function loadFromLocal() {
  let rawFunctions;

  try {
    if (fs.existsSync(config.functionPaths.bundle.snapshot) && fs.existsSync(config.functionPaths.bundle.date)) {
      debug('attempting to load the functions bundled with the package');
      rawFunctions = require(config.functionPaths.bundle.snapshot);
      vulnerabilitiesMetadata = processFunctionsToInspect(rawFunctions);
      lastModified = new Date(fs.readFileSync(config.functionPaths.bundle.date, 'utf8'));
      debug(`loaded the functions bundled with the package at ${lastModified.toUTCString()}`);
      return;
    }
  } catch (error) {
    debug('error loading the bundled functions, falling back to the snapshot provided in the repo');
    debug(error);
  }

  rawFunctions = require(config.functionPaths.repo.snapshot);
  vulnerabilitiesMetadata = processFunctionsToInspect(rawFunctions);
  lastModified = new Date(fs.readFileSync(config.functionPaths.repo.date, 'utf8'));
  debug(`loaded the functions provided in the repository, created at ${lastModified.toUTCString()}`);
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

    lastModified = new Date(response.headers['last-modified']);
    const rawSnapshot = response.body;
    vulnerabilitiesMetadata = processFunctionsToInspect(rawSnapshot);
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
      if (!(currentFunction.functionId.filePath in processedFunctions[currentFunction.packageName])) {
        processedFunctions[currentFunction.packageName][currentFunction.functionId.filePath] = [];
      }
      processedFunctions[currentFunction.packageName][currentFunction.functionId.filePath].push({
        name: currentFunction.functionId.functionName,
        semver: currentFunction.version,
        publicId: currentFunction.public_id,
      });
    } catch (err) {
      debug(`Failed inspecting ${currentFunction}:`, err);
    }
  });
  return processedFunctions;
}

//TODO: fix it hack for tests
function setVulnerabilitiesMetadata(vulnMetadata) {
  vulnerabilitiesMetadata = processFunctionsToInspect(vulnMetadata);
}
