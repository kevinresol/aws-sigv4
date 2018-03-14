package ;

import aws.sigv4.*;
import tink.http.Request;
import tink.http.Header;
import tink.streams.Stream;
import tink.Url;
import tink.unit.*;
import tink.testrunner.*;

using tink.io.Source;
using tink.CoreApi;
using sys.io.File;
using sys.FileSystem;
using StringTools;
using DateTools;

@:asserts
class RunTests {

  static function main() {
    Runner.run(TestBatch.make([
      new RunTests()
    ])).handle(Runner.exit);
  }
  
  function new() {}
  
  public function example() {
    var date = new Date(2013, 4, 24, 0, 0, 0);
    var secretAccessKey = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY';
    var request = new OutgoingRequestHeader(GET, 'https://examplebucket.s3.amazonaws.com/test.txt?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIAIOSFODNN7EXAMPLE%2F20130524%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Date=20130524T000000Z&X-Amz-Expires=86400&X-Amz-SignedHeaders=host', []);
    var region = 'us-east-1';
    var service = 's3';
    
    var canonicalRequest = SigV4.createCanonicalRequest(request);
    asserts.assert(canonicalRequest == 'GET\n/test.txt\nX-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIAIOSFODNN7EXAMPLE%2F20130524%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Date=20130524T000000Z&X-Amz-Expires=86400&X-Amz-SignedHeaders=host\nhost:examplebucket.s3.amazonaws.com\n\nhost\nUNSIGNED-PAYLOAD');
    var scope = SigV4.createScope(date, 'us-east-1', 's3');
    asserts.assert(scope == '20130524/us-east-1/s3/aws4_request');
    var stringToSign = SigV4.createStringToSign(date, scope, canonicalRequest);
    asserts.assert(stringToSign == 'AWS4-HMAC-SHA256\n20130524T000000Z\n20130524/us-east-1/s3/aws4_request\n3bfa292879f6447bbcda7001decf97f4a54dc650c8942174ae0a9121cf58ad04');
    var signingKey = SigV4.createSignatureKey(secretAccessKey, date, region, service);
    var signature = SigV4.createSignature(signingKey, stringToSign);
    asserts.assert(signature == 'aeeed9bbccd4d02ee5c0109b86d86835f995330da4c265957d157751f604d404');
    return asserts.done();
  }
  
  public function presignUrl() {
		var timezoneOffset = new Date(1970,0,1,0,0,0).getTime();
    var date = new Date(2013, 4, 24, 0, 0, 0).delta(-timezoneOffset);
    var accessKeyId = 'AKIAIOSFODNN7EXAMPLE';
    var secretAccessKey = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY';
    var request = new OutgoingRequestHeader(GET, 'https://examplebucket.s3.amazonaws.com/test.txt', []);
    var region = 'us-east-1';
    var service = 's3';
    
    var url = SigV4.presignUrl({
      request: request,
      region: region,
      service: service,
      secretAccessKey: secretAccessKey,
      accessKeyId: accessKeyId,
      expiry: 86400,
      date: date,
    });
    asserts.assert(url.toString() == 'https://examplebucket.s3.amazonaws.com/test.txt?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIAIOSFODNN7EXAMPLE%2F20130524%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Date=20130524T000000Z&X-Amz-Expires=86400&X-Amz-SignedHeaders=host&X-Amz-Signature=aeeed9bbccd4d02ee5c0109b86d86835f995330da4c265957d157751f604d404');
    return asserts.done();
  }
  
  // public function test() {
  //   var folder = 'tests/suite/aws-sig-v4-test-suite';
  //   Stream.ofIterator(folder.readDirectory().iterator()).forEach(function(suite) {
  //     var folder = '$folder/$suite';
  //     if(suite == 'normalize-path') return Resume;
  //     if(suite == 'post-sts-token') return Resume;
  //     if(!folder.isDirectory()) return Resume;
      
  //     var ref_req = '$folder/$suite.req'.getContent().replace('\n', '\r\n') + '\r\n\r\n';
  //     var ref_creq = '$folder/$suite.creq'.getContent();
      
  //     return IncomingRequest.parse('', ref_req)
  //       .next(function(req) {
  //         var req = new OutgoingRequest(
  //           new OutgoingRequestHeader(req.header.method, req.header.url, req.header.protocol, [for(h in req.header) h]),
  //           switch req.body {
  //             case Plain(s): s.idealize(function(_) return Source.EMPTY);
  //             case _: '';
  //           }
  //         );
  //         // trace('==========================');
  //         // trace(raw);
  //         // trace('--------------------------');
  //         var creq = SigV4.createCanonicalRequest(req).sure();
  //         trace('==== $suite ====');
  //         // trace(creq);
  //         // trace(ref_creq);
  //         trace(creq == ref_creq);
  //         // break;
  //         return Resume;
          
  //       })
  //       .recover(Clog);
      
  //   }).handle(function(o) {
  //     trace(o);
  //     asserts.done();
  //   });
    
  //   return asserts;
  // }
  
}