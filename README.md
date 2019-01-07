# Snyk Node.js runtime agent 

Use this package as a library in your application to monitor your dependencies and to learn how the vulnerable functions of the dependencies are invoked in your deployments.

# Quick start
```js
require('@snyk/nodejs-runtime-agent')({ projectId: <Your-Project-ID> });
```

# How to
```js
require('@snyk/nodejs-runtime-agent')(config);
```

The `config` object supports the following options:

| Key                | Type      | Default value                            | Purpose                                                                 |
|--------------------|-----------|------------------------------------------|-------------------------------------------------------------------------|
| `projectId`        | `String`  |                                          | The Snyk project ID that matches your application.                      |
| `enable`           | `Boolean` | `true`                                   | Set to `false` to disable the agent.                                    |

Advanced `config` options:

| Key                  | Type      | Default value                                               | Purpose                                                                                    |
|----------------------|-----------|-------------------------------------------------------------|--------------------------------------------------------------------------------------------|
| `beaconIntervalMs`   | `Number`  | `60000`                                                     | Report frequency in milliseconds.                                                          |
| `snapshotIntervalMs` | `Number`  | `3600000`                                                   | Snapshot retrieval frequency in milliseconds.                                              |

# Demo
`npm start` to bring up an http server that invokes a vulnerable function on startup and for every request.
