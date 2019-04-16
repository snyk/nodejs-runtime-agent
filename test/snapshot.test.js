const fs = require('fs');
const test = require('tap').test;
const nock = require('nock');
const sinon = require('sinon');
const path = require('path');
const needle = require('needle');

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

test('reader loading snapshot from upstream', async (t) => {
  nock('https://homebase.snyk.io')
    .get('/api/v2/snapshot/whatever/node')
    .reply(200, []);
  nock('https://homebase.snyk.io')
    .get('/api/v2/snapshot/whatever/node')
    .reply(200, []);

  const needleSpy = sinon.spy(needle, 'request');

  snapshotReader.loadFromUpstream();
  t.equal(needleSpy.args[0][0], 'get', 'snapshots retrieved with get');
  t.equal(needleSpy.args[0][1], 'https://homebase.snyk.io/api/v2/snapshot/whatever/node', 'url is correct');
  const expectedRequestOptions = {
    json: true,
    rejectUnauthorized: true,
    headers: {"If-Modified-Since": "Thu, 06 Dec 2018 14:02:33 GMT"},
  };
  t.deepEqual(needleSpy.args[0][3], expectedRequestOptions, 'request options are correct');

  config['allowUnknownCA'] = true;
  snapshotReader.loadFromUpstream();
  expectedRequestOptions.rejectUnauthorized = false;
  t.deepEqual(needleSpy.args[1][3], expectedRequestOptions, 'request options are correct');

  t.ok(nock.isDone(), 'snapshot requests made');
  nock.cleanAll();
});
