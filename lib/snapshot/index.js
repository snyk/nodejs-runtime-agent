const semver = require('semver');

const ast = require('../ast');
const reader = require('./reader');

let vulnerabiltiesMetadata = {};

function init() {
  const readFromLocalSnapshot = true;
  vulnerabiltiesMetadata = reader.getLatest(readFromLocalSnapshot);
}

function getVulnerableFunctionsLocations(moduleInfo) {
  const {name: packageName, version, scriptRelativePath, scriptPath} = moduleInfo;
  if (!((packageName in vulnerabiltiesMetadata) && (scriptRelativePath in vulnerabiltiesMetadata[packageName]))) {
    return {};
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
  vulnerabiltiesMetadata = reader.processFunctionsToInspect(vulnMetadata);
}

module.exports = {
  init,
  setVulnerabiltiesMetadata,
  getVulnerableFunctionsLocations,
};
