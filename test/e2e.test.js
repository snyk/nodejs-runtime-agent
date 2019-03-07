const test = require('tap').test;
const needle = require('needle');
const nock = require('nock');
const sleep = require('sleep-promise');
const path = require('path');

test('demo app reports a vuln method when called', async (t) => {
  const newSnapshotModificationDate = new Date();

  // first call will have one event triggered when the demo starts
  nock('http://localhost:8000')
    .post('/api/v1/beacon')
    .reply(200, (uri, requestBody) => {
      // assert the expected beacon data
      const beaconData = JSON.parse(requestBody);
      t.ok(beaconData.projectId, 'projectId present in beacon data');
      t.ok(beaconData.agentId, 'agentId present in beacon data');
      t.ok(beaconData.systemInfo, 'systemInfo present in beacon data');
      t.ok(!('error' in beaconData.systemInfo), 'systemInfo has no errors');
      t.ok(beaconData.eventsToSend, 'eventsToSend present in beacon data');
      t.equal(beaconData.eventsToSend.length, 1, 'one event sent');
      t.equal(beaconData.eventsToSend[0].methodEntry.methodName, 'mime.Mime.prototype.lookup', 'only vulnerability on startup is mime.lookup which st imports');
      const expectedFilters = {
        'st': {'st.js': {'Mount.prototype.getPath': null}},
        'mime': {'mime.js': {'Mime.prototype.lookup': null}},
        'negotiator': {'lib/language.js': {'parseLanguage': null}},
      };
      t.deepEqual(beaconData.filters, expectedFilters, 'instrumentation appears in beacon');
      t.ok(beaconData.loadedSources, 'loadedSources present in beacon data');
      t.ok('st' in beaconData.loadedSources, 'st was loaded');
      t.deepEqual(beaconData.loadedSources['st'], {'0.1.4': {}}, 'expected st version');
      t.ok('mime' in beaconData.loadedSources, 'mime was loaded');
      t.deepEqual(beaconData.loadedSources['mime'], {'1.2.11': {}}, 'expected mime version');
    });

  // second call will have an additional event because we trigger the vuln method
  nock('http://localhost:8000')
    .post('/api/v1/beacon')
    .reply(200, (uri, requestBody) => {

      // assert the expected beacon data
      const beaconData = JSON.parse(requestBody);
      t.ok(beaconData.projectId, 'projectId present in beacon data');
      t.ok(beaconData.agentId, 'agentId present in beacon data');
      t.ok(beaconData.systemInfo, 'systemInfo present in beacon data');
      t.ok(!('error' in beaconData.systemInfo), 'systemInfo has no errors');
      t.ok(beaconData.eventsToSend, 'eventsToSend present in beacon data');

      t.equal(beaconData.eventsToSend.length, 2, '2 events sent');
      const beaconEvent = beaconData.eventsToSend[0].methodEntry;
      t.ok(beaconEvent, 'method event sent');
      t.equal(beaconEvent.methodName, 'st.Mount.prototype.getPath', 'proper vulnerable method name');
      t.same(beaconEvent.coordinates, ['node:st:0.1.4'], 'proper vulnerable module coordinate');
      t.ok(beaconEvent.sourceUri.endsWith('/st.js'), 'proper vulnerable module script');
      t.ok(beaconEvent.sourceUri.includes(`node_modules${path.sep}st`), 'proper vulnerable module base dir');
      const secondBeaconEvent = beaconData.eventsToSend[1].methodEntry;
      t.ok(secondBeaconEvent, 'method event sent');
      t.equal(secondBeaconEvent.methodName, 'mime.Mime.prototype.lookup', 'proper vulnerable method name');
      t.same(secondBeaconEvent.coordinates, ['node:mime:1.2.11'], 'proper vulnerable module coordinate');
      t.ok(secondBeaconEvent.sourceUri.endsWith('/mime.js'), 'proper vulnerable module script');
      t.ok(secondBeaconEvent.sourceUri.includes(`node_modules${path.sep}st${path.sep}node_modules${path.sep}mime`), 'proper vulnerable module base dir');
      const expectedFilters = {
        'st': {'st.js': {'Mount.prototype.getPath': null}},
        'mime': {'mime.js': {'Mime.prototype.lookup': null}},
        'negotiator': {'lib/language.js': {'parseLanguage': null}},
      };
      t.deepEqual(beaconData.filters, expectedFilters, 'instrumentation appears in beacon');
      t.ok(beaconData.loadedSources, 'loadedSources present in beacon data');
      t.ok('st' in beaconData.loadedSources, 'st was loaded');
      t.deepEqual(beaconData.loadedSources['st'], {'0.1.4': {}}, 'expected st version');
      t.ok('mime' in beaconData.loadedSources, 'mime was loaded');
      t.deepEqual(beaconData.loadedSources['mime'], {'1.2.11': {}}, 'expected mime version');
    });

  // expecting a call to homebase for the newest snapshot
  nock('http://localhost:8000')
    .matchHeader('if-modified-since', (val) => {
      // making sure we got a Date here since I'm not sure what else to test in the 1st request
      try {
        new Date(val);
        return true;
      } catch (error) {
        return false;
      }
    })
    .get('/api/v2/snapshot/A3B8ADA9-B726-41E9-BC6B-5169F7F89A0C/node')
    .reply(200, () => {
      const baseVulnerableFunctions = require('../lib/resources/functions.repo.json');
      const newlyDiscoveredVulnerability = {
        functionId: {
          className: null,
          filePath: 'st.js',
          functionName: 'Mount.prototype.getUrl',
        },
        packageName: 'st',
        version: ['<0.2.5'],
      };
      const newSnapshot = baseVulnerableFunctions;
      newSnapshot.push(newlyDiscoveredVulnerability);
      return newSnapshot;
    }, {'Last-Modified': newSnapshotModificationDate.toUTCString()});

  // third call will have three events because we updated the snapshot
  nock('http://localhost:8000')
  .post('/api/v1/beacon')
  .reply(200, (uri, requestBody) => {
    // assert the expected beacon data
    const beaconData = JSON.parse(requestBody);
    t.ok(beaconData.projectId, 'projectId present in beacon data');
    t.ok(beaconData.agentId, 'agentId present in beacon data');
    t.ok(beaconData.systemInfo, 'systemInfo present in beacon data');
    t.ok(!('error' in beaconData.systemInfo), 'systemInfo has no errors');
    t.ok(beaconData.eventsToSend, 'eventsToSend present in beacon data');

    t.equal(beaconData.eventsToSend.length, 3, '3 events sent');
    const methodNames = [];
    methodNames.push(beaconData.eventsToSend[0].methodEntry.methodName);
    methodNames.push(beaconData.eventsToSend[1].methodEntry.methodName);
    methodNames.push(beaconData.eventsToSend[2].methodEntry.methodName);
    t.ok(methodNames.indexOf('st.Mount.prototype.getPath') !== -1);
    t.ok(methodNames.indexOf('st.Mount.prototype.getUrl') !== -1);
    t.ok(methodNames.indexOf('mime.Mime.prototype.lookup') !== -1);
    const expectedFilters = {
      'st': {'st.js': {'Mount.prototype.getPath': null, 'Mount.prototype.getUrl': null}},
      'mime': {'mime.js': {'Mime.prototype.lookup': null}},
      'negotiator': {'lib/language.js': {'parseLanguage': null}},
    };
    t.deepEqual(beaconData.filters, expectedFilters, 'instrumentation appears in beacon');
    t.ok(beaconData.loadedSources, 'loadedSources present in beacon data');
    t.ok('st' in beaconData.loadedSources, 'st was loaded');
    t.deepEqual(beaconData.loadedSources['st'], {'0.1.4': {}}, 'expected st version');
    t.ok('mime' in beaconData.loadedSources, 'mime was loaded');
    t.deepEqual(beaconData.loadedSources['mime'], {'1.2.11': {}}, 'expected mime version');
  });

  // expecting next call to homebase for new snapshot to contain different If-Modified-Since header
  nock('http://localhost:8000')
    .matchHeader('if-modified-since', newSnapshotModificationDate.toUTCString())
    .get('/api/v2/snapshot/A3B8ADA9-B726-41E9-BC6B-5169F7F89A0C/node')
    .reply(304, 'OK or whatever', {'Last-Modified': newSnapshotModificationDate.toUTCString()});

  const BEACON_INTERVAL_MS = 1000; // 1 sec agent beacon interval
  const SNAPSHOT_INTERVAL_MS = 2500; // retrieve newer snapshot every 2.5 seconds

  // configure agent in demo server via env vars
  process.env.SNYK_HOMEBASE_URL = 'http://localhost:8000/api/v1/beacon';
  process.env.SNYK_SNAPSHOT_URL = 'http://localhost:8000/api/v2/snapshot/A3B8ADA9-B726-41E9-BC6B-5169F7F89A0C/node';
  process.env.SNYK_BEACON_INTERVAL_MS = BEACON_INTERVAL_MS;
  process.env.SNYK_SNAPSHOT_INTERVAL_MS = SNAPSHOT_INTERVAL_MS;
  process.env.SNYK_TRIGGER_EXTRA_VULN = true;

  // bring up the demo server
  const demoApp = require('../demo');

  // wait to let the agent go through a cycle
  await sleep(BEACON_INTERVAL_MS);

  // trigger the vuln method
  await needle.get('http://localhost:3000/hello.txt');

  // wait to let the agent go through a cycle
  await sleep(BEACON_INTERVAL_MS);

  // wait until we refresh the snapshot
  await sleep(SNAPSHOT_INTERVAL_MS - BEACON_INTERVAL_MS * 2);

  // trigger the vuln method again
  await needle.get('http://localhost:3000/hello.txt');

  // wait to let the agent go through another cycle with a new snapshot
  await sleep(BEACON_INTERVAL_MS);

  // wait to let the agent request another snapshot even though he has the latest
  await sleep(SNAPSHOT_INTERVAL_MS);

  // make sure all beacon calls were made
  t.ok(nock.isDone(), 'all beacon call were made');

  delete process.env.SNYK_HOMEBASE_URL;
  delete process.env.SNYK_SNAPSHOT_URL;
  delete process.env.SNYK_BEACON_INTERVAL_MS;
  delete process.env.SNYK_SNAPSHOT_INTERVAL_MS;
  delete process.env.SNYK_TRIGGER_EXTRA_VULN;

  demoApp.close();
});
