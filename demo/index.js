// load the agent from the local project and start it
// env vars provide the configuration with default values as a fallback
require('../lib')({
  url: process.env.SNYK_HOMEBASE_URL || 'http://localhost:8000/api/v1/beacon',
  projectId: process.env.SNYK_PROJECT_ID || 'A3B8ADA9-B726-41E9-BC6B-5169F7F89A0C',
  beaconIntervalMs: process.env.SNYK_BEACON_INTERVAL_MS || 10000,
  enable: !process.env.SNYK_RUNTIME_AGENT_DISABLE,
});

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
