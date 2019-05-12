const test = require('tap').test;
const nock = require('nock');
const sinon = require('sinon');
const needle = require('needle');

const config = require('../lib/config');

test('Beacons and snapshots are sent to configured base url', async function(t) {
    config.initConfig({projectId: 'whatever', baseUrl: 'http://localhost:8000'});
    t.equal(config.beaconUrl, 'http://localhost:8000/api/v1/beacon', 'beacon url with prefix is correct')
    t.equal(config.snapshotUrl, 'http://localhost:8000/api/v2/snapshot/whatever/node', 'snapshot url with prefix is correct')
});
