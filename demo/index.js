// load the agent from the local project and start it
// env vars provide the configuration with default values as a fallback
require('../lib')({
  url: process.env.SNYK_HOMEBASE_URL || 'http://localhost:8000/api/v1/beacon',
  snapshotUrl: process.env.SNYK_SNAPSHOT_URL || 'http://localhost:8000/api/v2/snapshot/A3B8ADA9-B726-41E9-BC6B-5169F7F89A0C/node',
  projectId: process.env.SNYK_PROJECT_ID || 'A3B8ADA9-B726-41E9-BC6B-5169F7F89A0C',
  beaconIntervalMs: process.env.SNYK_BEACON_INTERVAL_MS || 10000,
  snapshotIntervalMs: process.env.SNYK_SNAPSHOT_INTERVAL_MS || 60 * 60 * 1000,
  enable: !process.env.SNYK_RUNTIME_AGENT_DISABLE,
});

// start running some non-vulnerable function in the background
// tests may hook into it to make it look vulnerable
if (process.env.SNYK_TRIGGER_EXTRA_VULN) {
  setInterval(() => {
    try {
      st.Mount.prototype.getUrl('whatever');
    } catch (err) {}
  }, 250).unref();
}

// create a server with a known vulnerability
const http = require('http');
const st = require('st');
const PORT = process.env.PORT || 3000;

const server = http.createServer(
  st({
    path: __dirname + '/static',
    url: '/',
    cors: true
  })
);

server.listen(PORT, () => console.log(`Demo server started, hit http://localhost:${PORT}/hello.txt to try it`));

module.exports = server;
