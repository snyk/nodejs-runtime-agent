const test = require('tap').test;
const sleep = require('sleep-promise');

const proxyquire =  require('proxyquire');


test('demo app reports a vuln method when called', async (t) => {
  const BEACON_INTERVAL_MS = 1000;
  process.env.SNYK_HOMEBASE_URL = 'http://localhost:8000/api/v1/beacon';
  process.env.SNYK_BEACON_INTERVAL_MS = BEACON_INTERVAL_MS;

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

  demoApp.close();
});
