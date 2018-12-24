const test = require('tap').test;
const nock = require('nock');
const path = require('path');
const sleep = require('sleep-promise');

const agentConfig = {
  projectId: 'hi',
  beaconIntervalMs: 1000,
  url: 'http://localhost:8000/api/v1/beacon',
  functionPaths: {
    repo: {
      snapshot: path.join(__dirname, 'fixtures/function-declarations/functions.repo.json'),
      date: path.join(__dirname, 'fixtures/function-declarations/build-date.repo'),
    },
    bundle: {
      snapshot: 'FILE/DOES/NOT/EXIST/EVER/EVER',
      date: 'FILE/DOES/NOT/EXIST/EVER/EVER',
    },
  },
};

test('function declaration variations', async (t) => {

  nock('http://localhost:8000')
    .post('/api/v1/beacon')
    .reply(200, (uri, requestBody) => {
      const beaconData = JSON.parse(requestBody);
      t.ok(beaconData.eventsToSend, 'eventsToSend present in beacon data');
      t.equal(beaconData.eventsToSend.length, 0, 'no events sent');
    });

  nock('http://localhost:8000')
    .post('/api/v1/beacon')
    .reply(200, (uri, requestBody) => {
      const beaconData = JSON.parse(requestBody);
      t.ok(beaconData.eventsToSend, 'eventsToSend present in beacon data');
      t.equal(beaconData.eventsToSend.length, 4, 'no events sent');
      t.equal(beaconData.eventsToSend[0].methodEntry.methodName, 'one-liner.f', 'one-liner method detected');
      t.equal(beaconData.eventsToSend[1].methodEntry.methodName, 'multiple-one-liners.f0', 'multiple-one-liners method detected');
      t.equal(beaconData.eventsToSend[2].methodEntry.methodName, 'multiple-one-liners.f10', 'multiple-one-liners method detected');
      t.equal(beaconData.eventsToSend[3].methodEntry.methodName, 'multiple-one-liners.f18', 'multiple-one-liners method detected');
    });

  // start the agent
  require('../lib')(agentConfig);

  // require vulnerable packages
  const oneLiner = require(path.join(__dirname, 'fixtures/function-declarations/node_modules/one-liner'));
  const multipleOneLiners = require(path.join(__dirname, 'fixtures/function-declarations/node_modules/multiple-one-liners'));

  // wait to let the agent go through a cycle
  await sleep(1000);

  // trigger vulnerable functions
  oneLiner.f();
  multipleOneLiners.f0();
  multipleOneLiners.f10();
  multipleOneLiners.f18();

  // wait to let the agent go through another cycle
  await sleep(1000);

  t.ok(nock.isDone(), 'all beacon call were made');
});
