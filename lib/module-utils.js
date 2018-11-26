const fs = require('fs');
const path = require('path');

function isNative(filePath) {
  return !filePath.includes('node_modules');
}

function getModuleInfo(filePath) {
  const segments = filePath.split(path.sep);
  const index = segments.lastIndexOf('node_modules');
  const scoped = segments[index + 1][0] === '@';
  const offset = scoped ? 3 : 2;
  const baseDir = segments.slice(0, index + offset).join(path.sep);
  const packageJsonStr = fs.readFileSync(path.join(baseDir, 'package.json'));
  const packageJson = JSON.parse(packageJsonStr);
  const moduleInfo = {
    version: packageJson.version,
    name: packageJson.name,
    baseDir: baseDir,
    scriptRelativePath: segments.slice(index + offset).join(path.sep),
  };
  return moduleInfo;
}

function normalizeScriptPath(scriptPath) {
  // Remove file prefix which was added in Node v10.12
  if (scriptPath.startsWith('file://') && path.sep === '/') {
    scriptPath = scriptPath.substring('file://'.length);
  } else if (scriptPath.startsWith('file:///') && path.sep === '\\') {
    scriptPath = scriptPath.substring('file:///'.length).replace(/\//g, '\\');
  }
  return scriptPath;
}

module.exports = {isNative, getModuleInfo, normalizeScriptPath};
