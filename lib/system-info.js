const os = require('os');

const packageJson = require('../package.json');

function getSystemInfo() {
  let systemInfo = {agentVersion: packageJson.version || ''};

  try {
    systemInfo.hostName = os.hostname();
    systemInfo.node = {versions: process.versions},
    systemInfo.os = {
      type: os.type(),
      release: os.release(),
      platform: os.platform(),
    };
  } catch (error) {
    systemInfo.error = `failed getting system info: ${error}`;
  }

  return systemInfo;
}

module.exports = {getSystemInfo};
