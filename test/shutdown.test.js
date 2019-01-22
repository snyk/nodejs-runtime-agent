const test = require('tap').test;
const http = require('http');
const spawn = require('child_process').spawn;

test('agent transmits before exit by default', t => {
  t.plan(3);

  // small server the agent can report to, upon exit
  const server = http.createServer(function (req, res) {
    t.equal(req.url, '/api/v1/beacon', 'agent reported before shutting down');
    t.equal(req.method, 'POST');
    t.equal(req.headers.host, 'localhost:9000');
    res.writeHead(200, {'Content-Type': 'text/plain'});
    res.end('carry on my wayward son!');
  }).listen(9000)

  // bring up the demo server, then close it
  var env = Object.create( process.env );
  env.DEBUG = 'snyk*';
  env.flushBeforeExit = 'yes';
  env.runtimeAgentPort = 9000;
  const demoApp = spawn('node',  ['demo/justrequireagent.js'], {env: env});

  // these snippets are nice for debugging the test
  // but seem to affect the behaviour of tap :scream:
  // demoApp.stdout.on('data', function (data) {
  //   var str = data.toString()
  //   var lines = str.split(/(\r?\n)/g);
  //   console.log(lines.join(""));
  // });
  // demoApp.stderr.on('data', function (data) {
  //   var str = data.toString()
  //   var lines = str.split(/(\r?\n)/g);
  //   console.log(lines.join(""));
  // });

  demoApp.on('close', function (code) {
    server.close();
  });
});

test('allow turning flushBeforeExit off', t => {
  // small server the agent can report to, upon exit
  const server = http.createServer(function (req, res) {
    t.fail('agent should not have reported');
    res.writeHead(200, {'Content-Type': 'text/plain'});
    res.end('shame on you!');
  }).listen(9001)

  // bring up the demo server, then close it
  var env = Object.create( process.env );
  env.DEBUG = 'snyk*';
  env.flushBeforeExit = 'plz no';
  env.runtimeAgentPort = 9001;
  const demoApp = spawn('node',  ['demo/justrequireagent.js'], {env: env});

  demoApp.on('close', function (code) {
    t.end();
    server.close();
  });
});
