const fs = require('fs');
const path = require('path');
const debug = require('debug')('snyk:nodejs-runtime-agent');

const FUNCTIONS_METATDATA_FILE = path.join(__dirname, '../../functions-to-track-runtime.json');

module.exports = {
  getLatest,
  processFunctionsToInspect,
};

function getLatest() {
  return getFunctionsToInspect();
}

function getFunctionsToInspect() {
  const appDir = path.dirname(require.main.filename);
  const appMetadataFilePath = path.join(appDir, 'functions-to-track-runtime.json');
  const exists = fs.existsSync(appMetadataFilePath);

  if (!exists) {
    return processFunctionsToInspect(require(FUNCTIONS_METATDATA_FILE));
  }

  debug('Using app defined method.json to load vulnerabilties');
  return processFunctionsToInspect(require(appMetadataFilePath));
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
