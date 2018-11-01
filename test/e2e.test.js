const test = require('tap').test;
const needle = require('needle');
const nock = require('nock');
const sleep = require('sleep-promise');
const path = require('path');

test('demo app reports a vuln method when called', async (t) => {
  // first call will have no events
  nock('http://localhost:8000')
    .post('/api/v1/beacon')
    .reply(200, (uri, requestBody) => {
      // assert the expected beacon data
      const beaconData = JSON.parse(requestBody);
      t.ok(beaconData.projectId, 'projectId present in beacon data');
      t.ok(beaconData.agentId, 'agentId present in beacon data');
      t.ok(beaconData.eventsToSend, 'eventsToSend present in beacon data');
      t.equal(beaconData.eventsToSend.length, 1, 'one event sent');
      t.equal(beaconData.eventsToSend[0].methodEntry.methodName, 'mime.Mime.prototype.lookup', 'only vulnerability on startup is mime.lookup which st imports');
    });

  // second call will have an event for the newly invoked getPath but not previously invoked lookup
  nock('http://localhost:8000')
    .post('/api/v1/beacon')
    .reply(200, (uri, requestBody) => {
      // assert the expected beacon data
      const beaconData = JSON.parse(requestBody);
      t.ok(beaconData.projectId, 'projectId present in beacon data');
      t.ok(beaconData.agentId, 'agentId present in beacon data');
      t.ok(beaconData.eventsToSend, 'eventsToSend present in beacon data');

      t.equal(beaconData.eventsToSend.length, 1, '1 event sent');
      const beaconEvent = beaconData.eventsToSend[0].methodEntry;
      t.ok(beaconEvent, 'method event sent');
      t.equal(beaconEvent.methodName, 'st.Mount.prototype.getPath', 'proper vulnerable method name');
      t.same(beaconEvent.coordinates, ['node:st:0.1.4'], 'proper vulnerable module coordinate');
      t.ok(beaconEvent.sourceUri.endsWith('/st.js'), 'proper vulnerable module script');
      t.ok(beaconEvent.sourceUri.includes(`node_modules${path.sep}st`), 'proper vulnerable module base dir');
    });

  const BEACON_INTERVAL_MS = 1000; // 1 sec agent beacon interval
  // configure agent in demo server via env vars
  process.env.SNYK_HOMEBASE_URL = 'http://localhost:8000/api/v1/beacon';
  process.env.SNYK_BEACON_INTERVAL_MS = BEACON_INTERVAL_MS;
  process.env.SNYK_SNOOZE_METHOD_MS = 100000;

  // bring up the demo server
  const demoApp = require('../demo');

  // wait to let the agent go through a cycle
  await sleep(BEACON_INTERVAL_MS);

  // trigger the vuln method
  await needle.get('http://localhost:3000/hello.txt');

  // wait to let the agent go through a cycle
  await sleep(BEACON_INTERVAL_MS);

  // make sure all beacon calls were made
  t.ok(nock.isDone(), 'all beacon call were made');

  delete process.env.SNYK_HOMEBASE_URL;
  delete process.env.SNYK_BEACON_INTERVAL_MS;
  delete process.env.SNYK_SNOOZE_METHOD_MS;

  demoApp.close();
});
