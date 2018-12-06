const fs = require('fs');
const test = require('tap').test;
const sinon = require('sinon');

const config = require('../lib/config');
const snapshotReader = require('../lib/snapshot/reader');

config.initConfig({projectId: 'whatever'});

// TODO

  // sinon.stub(config, 'functionPaths').returns({
  //   repo: {
  //     snapshot: path.join(__dirname, './resources/functions.repo.json'),
  //     date: path.join(__dirname, './resources/build-date.repo'),
  //   },
  //   bundle: {
  //     snapshot: path.join(__dirname, './resources/functions.bundle.json'),
  //     date: path.join(__dirname, './resources/build-date.bundle'),
  //   },
  // });

test('snapshot reader defaults to repo snapshot when bundled is missing', async (t) => {
  const repoSnapshotStub = [{
    "methodId": {
      "className": null,
      "filePath": "mime.js",
      "methodName": "Mime.prototype.lookup"
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
});

test('snapshot reader falls back to repo snapshot when bundled errors', async (t) => {

});

test('snapshot reader favours bundled snapshot when possible', async (t) => {

});
