const flushOnExit = process.env.flushBeforeExit ? process.env.flushBeforeExit === 'yes' : true;
const port = process.env.runtimeAgentPort || 9000;

// load the agent
require('../lib')({
  url: `http://localhost:${port}/api/v1/beacon`,
  projectId: 'hurr durr',
  flushOnExit,
});

// do some.. stuff
console.log('henlo!');
let i = 0;
while (i < 100) {
  i += 1;
}

// and.. we're done!
console.log('ok bye');
