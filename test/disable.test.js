const test = require('tap').test;
const needle = require('needle');
const nock = require('nock');
const sleep = require('sleep-promise');

test('agent can be disabled', async (t) => {
  // intercept potential beacons
  nock('http://localhost:7000')
    .post('/api/v1/beacon')
    .reply(200);

  const BEACON_INTERVAL_MS = 1000; // 1 sec agent beacon interval
  // configure agent in demo server via env vars
  process.env.SNYK_HOMEBASE_URL = 'http://localhost:7000/api/v1/beacon';
  process.env.SNYK_BEACON_INTERVAL_MS = BEACON_INTERVAL_MS;
  process.env.SNYK_RUNTIME_AGENT_DISABLE = 'yes please';

  // bring up the demo server
  const demoApp = require('../demo');

  // wait to let the agent go through a cycle
  await sleep(BEACON_INTERVAL_MS);

  // trigger the vuln method
  await needle.get('http://localhost:3000/hello.txt');

  // wait to let the agent go through a cycle
  await sleep(BEACON_INTERVAL_MS);

  // make sure no beacon calls were made
  t.ok(!nock.isDone(), 'no beacon calls were made');

  delete process.env.SNYK_HOMEBASE_URL;
  delete process.env.SNYK_BEACON_INTERVAL_MS;
  delete process.env.SNYK_RUNTIME_AGENT_DISABLE;

  demoApp.close();
});
