var http = require('http');
var url = require('url');
var fs = require('fs');
var process = require('process');

var devNull = fs.createWriteStream('/dev/null');
process.stderr.write = devNull.write.bind(devNull);

http.createServer(function(request, response) {
      console.log(request.method + " " + request.url + "\n");
      var url_parts = url.parse(request.url);
      var proxy = http.createClient(80, request.headers['host'])
      var proxy_request = proxy.request(request.method, request.url, request.headers);
      proxy_request.on('response', function (proxy_response) {
          
          proxy_response.on('data', function(chunk) {
              response.write(chunk, 'binary');
          });

          proxy_response.on('end', function() {
              response.end();
          });
          
          response.writeHead(proxy_response.statusCode, proxy_response.headers);
      });

      request.on('data', function(chunk) {
          console.log(chunk.toString('utf-8') + "\n");
          proxy_request.write(chunk, 'binary');
      });
      request.on('end', function() {
          proxy_request.end();
      });
}).listen(8080, function() {
    console.log("NetProxy listening on *:8080");    
});
