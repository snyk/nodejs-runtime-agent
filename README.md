# Snyk Nodejs Runtime Agent 

Use this package as a library in your application to monitor your dependencies and learn how the dependencies' vulnerable methods are being invoked in your deployments.

# Howto
```js
require('@snyk/nodejs-runtime-agent')(config);
```

The `config` object supports the following options:

| Key                | Type      | Default value                            | Purpose                                                                 |
|--------------------|-----------|------------------------------------------|-------------------------------------------------------------------------|
| `projectId`        | `String`  |                                          | The Snyk project ID matching to your application.                       |
| `enable`           | `Boolean` | `true`                                   | Set to `false` to disable the agent.                                    |
| `url`              | `String`  | `https://homebase.snyk.io/api/v1/beacon` | Override to have the agent report its beacons to an alternative server. |
| `beaconIntervalMs` | `Number`  | `60000`                                  | Beacon interval duration in milliseconds.                               |

# Demo
`npm start` to bring up an http server that invokes a vulnerable method on every request.
