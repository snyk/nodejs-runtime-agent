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
      t.equal(beaconData.eventsToSend.length, 8, 'no events sent');
      t.equal(beaconData.eventsToSend[0].methodEntry.methodName, 'one-liner.f', 'one-liner method detected');
      t.equal(beaconData.eventsToSend[1].methodEntry.methodName, 'multiple-one-liners.f0', 'multiple-one-liners method detected');
      t.equal(beaconData.eventsToSend[2].methodEntry.methodName, 'multiple-one-liners.f10', 'multiple-one-liners method detected');
      t.equal(beaconData.eventsToSend[3].methodEntry.methodName, 'multiple-one-liners.f18', 'multiple-one-liners method detected');
      t.equal(beaconData.eventsToSend[4].methodEntry.methodName, 'class-member.Moog.prototype.f', 'class member method detected');
      t.equal(beaconData.eventsToSend[5].methodEntry.methodName, 'multiple-declarations-in-exports.module.exports.f0', 'multiple-declarations-in-exports method detected');
      t.equal(beaconData.eventsToSend[6].methodEntry.methodName, 'multiple-declarations-in-exports.module.exports.f4', 'multiple-declarations-in-exports method detected');
      t.equal(beaconData.eventsToSend[7].methodEntry.methodName, 'multiple-declarations-in-exports.module.exports.f9', 'multiple-declarations-in-exports method detected');
      // not supported yet
      // t.equal(beaconData.eventsToSend[8].methodEntry.methodName, 'one-liner-declaration-in-exports.module.exports.f', 'one-liner-declaration-in-exports method detected');
    });

  // start the agent
  require('../lib')(agentConfig);

  // require vulnerable packages
  const oneLiner = require('./fixtures/function-declarations/node_modules/one-liner');
  const multipleOneLiners = require('./fixtures/function-declarations/node_modules/multiple-one-liners');
  const classMember = require('./fixtures/function-declarations/node_modules/class-member');
  const multipleDeclarationInExports = require('./fixtures/function-declarations/node_modules/multiple-declarations-in-exports');
  // not supported yet
  // const oneLinerDeclarationInExports = require('./fixtures/function-declarations/node_modules/one-liner-declaration-in-exports');

  // wait to let the agent go through a cycle
  await sleep(1000);

  // trigger vulnerable functions
  oneLiner.f();
  multipleOneLiners.f0();
  multipleOneLiners.f10();
  multipleOneLiners.f18();
  classMember.f();
  multipleDeclarationInExports.f0();
  multipleDeclarationInExports.f4();
  multipleDeclarationInExports.f9();
  // not supported yet
  // oneLinerDeclarationInExports.f();

  // wait to let the agent go through another cycle
  await sleep(1000);

  t.ok(nock.isDone(), 'all beacon call were made');
});
