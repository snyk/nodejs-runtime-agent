const fs = require('fs');
const path = require('path');

function isNative(scriptPath) {
  const normalizedScriptPath = normalizeScriptPath(scriptPath);
  return !normalizedScriptPath.includes('node_modules');
}

function getModuleInfo(scriptPath) {
  const normalizedscriptPath = normalizeScriptPath(scriptPath);
  const segments = normalizedscriptPath.split(path.sep);
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
    scriptPath: normalizedscriptPath,
  };
  return moduleInfo;
}

function normalizeScriptPath(scriptPath) {
  let normalizedScriptPath = scriptPath;

  // Remove file prefix which was added in Node v10.12
  if (scriptPath.startsWith('file://') && path.sep === '/') {
    normalizedScriptPath = scriptPath.substring('file://'.length);
  } else if (scriptPath.startsWith('file:///') && path.sep === '\\') {
    normalizedScriptPath = scriptPath.substring('file:///'.length).replace(/\//g, '\\');
  }
  return normalizedScriptPath;
}

function normaliseSeparator(pathToNormalise) {
  if (path.sep === '\\') {
    return pathToNormalise.replace(/\//g, '\\');
  }
  return pathToNormalise;
}

function denormaliseSeparator(pathToDenormalise) {
  if (path.sep === '\\') {
    return pathToDenormalise.replace(/\\/g, '/');
  }
  return pathToDenormalise;
}

module.exports = {isNative, getModuleInfo, normaliseSeparator, denormaliseSeparator};
