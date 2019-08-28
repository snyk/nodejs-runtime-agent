const test = require('tap').test;
const sleep = require('sleep-promise');

const proxyquire =  require('proxyquire');

test('node agent does not crash the demo app', async (t) => {
  const BEACON_INTERVAL_MS = 1000;
  process.env.SNYK_HOMEBASE_URL = 'http://localhost:8000/api/v1/beacon';
  process.env.SNYK_BEACON_INTERVAL_MS = BEACON_INTERVAL_MS;
  // 0: let the OS pick a free port
  process.env.PORT = 0;

  // bring up the demo server, will fail on periodic tasks
  const demoApp = proxyquire('../demo', {
    '../lib': proxyquire('../lib', {
      './debugger-wrapper': {
        resumeSnoozedBreakpoints: () => {
          throw new Error("periodic failure");
        },
      },
    }),
  });

  // wait to let the agent go through a cycle
  await sleep(BEACON_INTERVAL_MS * 1);

  delete process.env.SNYK_HOMEBASE_URL;
  delete process.env.SNYK_BEACON_INTERVAL_MS;
  delete process.env.PORT;

  await new Promise((resolve) => demoApp.close(resolve));
});

test('node agent does not crash the demo app', async (t) => {
  const BEACON_INTERVAL_MS = 1000;
  process.env.SNYK_HOMEBASE_ORIGIN = 'http://localhost:-1';
  process.env.SNYK_BEACON_INTERVAL_MS = BEACON_INTERVAL_MS;
  process.env.SNYK_SNAPSHOT_INTERVAL_MS = 200;
  // 0: let the OS pick a free port
  process.env.PORT = 0;

  // bring up the demo server, will fail on any outgoing request
  const demoApp = require('../demo');

  // wait to let the agent go through a cycle
  await sleep(BEACON_INTERVAL_MS);

  delete process.env.SNYK_HOMEBASE_ORIGIN;
  delete process.env.SNYK_SNAPSHOT_INTERVAL_MS;
  delete process.env.SNYK_BEACON_INTERVAL_MS;
  delete process.env.PORT;

  await new Promise((resolve) => demoApp.close(resolve));
});
