// load the agent from the local project and start it
require('../lib')({
  url: 'http://localhost:8000/api/v1/beacon',
  projectId: 12345,
  debug: true,
});

// create a server with a known vulnerability
const http = require('http');
const st = require('st');
const PORT = process.env.PORT || 3000;


http.createServer(
  st({
    path: __dirname + '/static',
    url: '/',
    cors: true
  })
).listen(PORT, () => console.log(`Demo server started, hit http://localhost:${PORT}/hello.txt to try it`));
