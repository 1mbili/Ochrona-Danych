var http = require('http');
var url = require('url');
var fs = require('fs');

http.createServer(function (request, response) {
  var first = decodeURI(request.url)
  console.log(first)
  var lookup = url.parse(decodeURI(request.url)).pathname;
  lookup = (lookup === "/") ? '/index.html' : lookup;
  var f = 'content' + lookup;
  console.log('f: ' + f);

  const { spawn } = require('child_process');
  
  if (!f.endsWith(".txt")) {
    response.end('Illegal filename, only *.txt files allowed');
  }

  const child = spawn('cat', [f]);
  child.stdout.on("data", (data) => {
    response.end(data.toString());
  });

  child.stderr.on("data", (data) => {
    response.end(data.toString());
  });

  child.on('exit', function (code, signal) {
    console.log('child process exited with ' +
                `code ${code} and signal ${signal}`);
  });
}).listen(8080);

