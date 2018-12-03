const debug = require('debug')('snyk:nodejs-runtime-agent:snapshot');
const fs = require('fs');
const semver = require('semver');

const ast = require('../ast');
const reader = require('./reader');

function init() {
  reader.loadFromLocal();
}

function refresh() {
  return reader.loadFromUpstream()
    .then(() => {})
    .catch((error) => {
      // TODO - log? ignore?
    });
}

function getVulnerableFunctionsLocations(moduleInfo) {
  const vulnerabiltiesMetadata = reader.getLatest();
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

  try {
    return ast.findAllVulnerableFunctionsInScript(
      fs.readFileSync(scriptPath), vulnerableFunctionNames);
  } catch (error) {
    debug(`Error finding vulnerable methods ${vulnerableFunctionNames}` +
      ` in script path ${scriptPath}: ${error}`);
    return {};
  }
}

module.exports = {
  init,
  refresh,
  getVulnerableFunctionsLocations,
};
