// VULN: command-injection
// Fixture: OS command injection and eval

const { exec } = require('child_process');

function listFiles(userInput) {
  exec("ls " + userInput, (err, stdout) => {
    console.log(stdout);
  });
}

function runUserCode(userInput) {
  // Unsafe: eval on user input
  return eval(userInput);
}

module.exports = { listFiles, runUserCode };
