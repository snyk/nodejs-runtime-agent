const fs = require('fs');
const debug = require('debug')('snyk:nodejs-runtime-agent:snapshot');
const semver = require('semver');

const ast = require('../ast');
const reader = require('./reader');
const state = require('../state');

function init() {
  reader.loadFromLocal();
}

function refresh() {
  return reader.loadFromUpstream()
    .then(() => {})
    .catch(() => {});
}

function getVulnerableFunctionsLocations(moduleInfo) {
  const vulnerabilitiesMetadata = reader.getLatest();
  const {name: packageName, version, scriptRelativePath, scriptPath} = moduleInfo;
  if (!((packageName in vulnerabilitiesMetadata) && (scriptRelativePath in vulnerabilitiesMetadata[packageName]))) {
    return {};
  }

  const vulnerableFunctionNames = [];
  const scriptPathFunctions = vulnerabilitiesMetadata[packageName][scriptRelativePath];
  scriptPathFunctions.forEach(value => {
    value.semver.some(ver => {
      if (semver.satisfies(version, ver)) {
        vulnerableFunctionNames.push(value.name);
        return true;
      }

      return false;
    });
  });

  try {
    const vulnerableFunctionsFound = ast.findAllVulnerableFunctionsInScript(
      fs.readFileSync(scriptPath), vulnerableFunctionNames);
    const foundFunctionNames = Object.keys(vulnerableFunctionsFound);
    validateFoundFunctions(scriptPathFunctions, moduleInfo, vulnerableFunctionNames, foundFunctionNames);
    return vulnerableFunctionsFound;
  } catch (error) {
    debug(`Error finding vulnerable methods ${vulnerableFunctionNames}` +
      ` in script path ${scriptPath}: ${error}`);
    return {};
  }
}

function validateFoundFunctions(scriptPathFunctions, moduleInfo, functionsExpected, functionsActual) {
  const functionsNotFound = functionsExpected.filter(f => !functionsActual.includes(f));
  if (functionsNotFound && functionsNotFound.length > 0) {
    const warningEvent = {
      message: 'instrumentation discrepancy: missing functions from source code',
      moduleInfo,
      snapshotInfo: scriptPathFunctions,
      functionsInfo: {
        functionsExpected,
        functionsActual,
        functionsNotFound,
      },
    };
    state.addEvent({warning: warningEvent});
  }
}

module.exports = {
  init,
  refresh,
  getVulnerableFunctionsLocations,
};
