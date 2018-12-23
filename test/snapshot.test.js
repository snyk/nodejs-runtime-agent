const fs = require('fs');
const test = require('tap').test;
const sinon = require('sinon');
const path = require('path');

const config = require('../lib/config');
const snapshotReader = require('../lib/snapshot/reader');

config.initConfig({projectId: 'whatever'});

test('snapshot reader defaults to repo snapshot when bundled is missing', async (t) => {
  const repoSnapshotStub = [{
    "functionId": {
      "className": null,
      "filePath": "mime.js",
      "functionName": "Mime.prototype.lookup"
    },
    "packageName": "mime",
    "version": ["<1.4.1"]
  }];
  const stub = sinon.stub(fs, 'readFileSync');
  stub.withArgs(config.functionPaths.repo.snapshot).returns(JSON.stringify(repoSnapshotStub));

  snapshotReader.loadFromLocal();
  const result = snapshotReader.getLatest();

  t.deepEqual(Object.keys(result), ['mime']);
  t.deepEqual(Object.keys(result['mime']), ['mime.js']);
  stub.restore();
  t.end();
});

function readerFallsBackToRepoSnapshotWhenBundledError(t, bundledResponse) {
  const repoSnapshotStub = [{
    "functionId": {
      "className": null,
      "filePath": "mime.js",
      "functionName": "Mime.prototype.lookup"
    },
    "packageName": "mime",
    "version": ["<1.4.1"]
  }];

  config.functionPaths.bundle.snapshot = path.join(__dirname, './fixtures/snapshots/bundled-snapshot.json'); //Just needs to point to an existing file
  const stub = sinon.stub(fs, 'readFileSync');
  stub.withArgs(config.functionPaths.repo.snapshot).returns(JSON.stringify(repoSnapshotStub));
  stub.withArgs(config.functionPaths.bundle.snapshot).returns(bundledResponse);

  const existsStub = sinon.stub(fs, 'existsSync').returns(true);

  snapshotReader.loadFromLocal();
  const result = snapshotReader.getLatest();

  t.deepEqual(Object.keys(result), ['mime']);
  t.deepEqual(Object.keys(result['mime']), ['mime.js']);
  
  stub.restore();
  existsStub.restore();
}

test('snapshot reader falls back to repo snapshot when bundled errors', async (t) => {
  readerFallsBackToRepoSnapshotWhenBundledError(t, ''); //Empty bundle
  readerFallsBackToRepoSnapshotWhenBundledError(t, 'Not a valid json'); //Invalid json
  readerFallsBackToRepoSnapshotWhenBundledError(t, '{t]}'); //Invalid json
  t.end();
});

test('snapshot reader favours bundled snapshot when possible', async (t) => {
  const bundleSnapshotStub = [{
    "functionId": {
      "className": null,
      "filePath": "bundle.js",
      "functionName": "bundle.prototype.lookup"
    },
    "packageName": "bundle",
    "version": ["<1.4.1"]
  }];

  config.functionPaths.bundle.snapshot = path.join(__dirname, './fixtures/snapshots/bundled-snapshot.json'); //Just needs to point to an existing file
  const stub = sinon.stub(fs, 'readFileSync');
  stub.withArgs(config.functionPaths.bundle.snapshot).returns(JSON.stringify(bundleSnapshotStub));
  stub.withArgs(config.functionPaths.bundle.date).returns('Thu, 06 Dec 2018 14:02:33 GMT');
  const existsStub = sinon.stub(fs, 'existsSync').returns(true);

  snapshotReader.loadFromLocal();
  const result = snapshotReader.getLatest();

  t.deepEqual(Object.keys(result), ['bundle']);
  t.deepEqual(Object.keys(result['bundle']), ['bundle.js']);

  stub.restore();
  existsStub.restore();
  t.end();
});
