# Snyk Nodejs Runtime Agent 

Use this package as a library in your application to monitor your dependencies and learn how the dependencies' vulnerable methods are being invoked in your deployments.

# Howto
```js
require('@snyk/nodejs-runtime-agent')({
  url: 'https://homebase.snyk.io/api/v1/beacon',
  projectId: `your project ID from snyk.io`,
});
```

# Demo
`npm start` to bring up an http server that invokes a vulnerable method on every request.
