const fs = require('fs');
const path = require('path');
const debug = require('debug')('snyk:nodejs-runtime-agent');
const semver = require('semver');

const ast = require('./ast');

const FUNCTIONS_METATDATA_FILE = path.join(__dirname, '../functions-to-track-runtime.json');
let vulnerabiltiesMetadata = {};

function loadsFunctionsToInspect() {
  const appDir = path.dirname(require.main.filename);
  const appMetadataFilePath = path.join(appDir, 'functions-to-track-runtime.json');
  const exists = fs.existsSync(appMetadataFilePath);
  if (!exists) {
    vulnerabiltiesMetadata = processFunctionsToInspect(require(FUNCTIONS_METATDATA_FILE));
  } else {
    debug('Using app defined method.json to load vulnerabilties');
    vulnerabiltiesMetadata = processFunctionsToInspect(require(appMetadataFilePath));
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

function getVulnerableFunctionsLocations(moduleInfo, scriptPath) {
  const {name: packageName, version, scriptRelativePath} = moduleInfo;
  if (!((packageName in vulnerabiltiesMetadata) && (scriptRelativePath in vulnerabiltiesMetadata[packageName]))) {
    return [];
  }

  const vulnerableFunctionNames = [];
  const scriptPathFunctions = vulnerabiltiesMetadata[packageName][scriptRelativePath];
  scriptPathFunctions.forEach(value => {
    value.semver.some(ver => {
      if (semver.satisfies(version, ver)) {
        vulnerableFunctionNames.push(value.name);
        return true;
      }

      return false;
    });
  });

  const functionsLocationInScript = ast.findAllVulnerableFunctionsInScriptPath(
    scriptPath, vulnerableFunctionNames);
  return functionsLocationInScript;
}

//TODO: fix it hack for tests
function setVulnerabiltiesMetadata(vulnMetadata) {
  vulnerabiltiesMetadata = processFunctionsToInspect(vulnMetadata);
}

module.exports = {
  setVulnerabiltiesMetadata,
  loadsFunctionsToInspect,
  getVulnerableFunctionsLocations,
};
