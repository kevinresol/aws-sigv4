package aws.sigv4;

import tink.http.Request;
import tink.http.Header;
import tink.Url;
import haxe.io.Bytes;
import haxe.crypto.*;

using StringTools;
using DateTools;

using tink.CoreApi;

class SigV4 {
	static inline var ALGORITHM = 'AWS4-HMAC-SHA256';
	
	public static function presignUrl(options:{
		request:OutgoingRequestHeader,
		region:String,
		service:String,
		secretAccessKey:String,
		accessKeyId:String,
		?sessionToken:String,
		?expiry:Int,
		?date:Date,
		?payload:String,
	}) {
		
		var date = options.date == null ? Date.now() : options.date;
		var timezoneOffset = new Date(1970,0,1,0,0,0).getTime();
		date = date.delta(timezoneOffset); // offset it so that when formatted to string we get UTC
		
		var scope = createScope(date, options.region, options.service);
		var query = (options.request.url.query == null ? '' : options.request.url.query + '&') 
			+  'X-Amz-Algorithm=$ALGORITHM'
			+ '&X-Amz-Credential=${StringTools.urlEncode(options.accessKeyId + '/' + scope)}'
			+ '&X-Amz-Date=${date.format('%Y%m%dT%H%M%SZ')}'
			+ (options.expiry == null ? '' : '&X-Amz-Expires=${options.expiry}')
			+ '&X-Amz-SignedHeaders=host'
			;
		
		var request = new OutgoingRequestHeader(options.request.method, replaceQuery(options.request.url, query), [for(h in options.request) h]);
		var canonicalRequest = createCanonicalRequest(request, options.payload);
		var stringToSign = createStringToSign(date, scope, canonicalRequest);
		var signingKey = createSignatureKey(options.secretAccessKey, date, options.region, options.service);
		var signature = createSignature(signingKey, stringToSign);
		
		return replaceQuery(
			request.url,
			request.url.query 
			+ '&X-Amz-Signature=$signature' 
			+ (options.sessionToken == null ? '' : '&X-Amz-Security-Token=${options.sessionToken}')
		);
	}
	
	static function replaceQuery(url:Url, query:String) {
		return Url.make({
			path: url.path,
			query: query,
			host: url.host,
			hosts: url.hosts,
			auth: url.auth,
			scheme: url.scheme,
			hash: url.hash,
		});
	}
	
	static function createScope(date:Date, region:String, service:String) {
		return '${date.format('%Y%m%d')}/$region/$service/aws4_request';
	}
	
	static function createStringToSign(date:Date, scope:String, canonicalRequest:String) {
		return '$ALGORITHM\n${date.format('%Y%m%dT%H%M%SZ')}\n$scope\n${Sha256.encode(canonicalRequest)}';
	}
	
	static function createSignature(signingKey:Bytes, stringToSign:String) {
		return new Hmac(SHA256).make(signingKey, Bytes.ofString(stringToSign)).toHex();
	}
	
	static function createCanonicalRequest(req:OutgoingRequestHeader, ?signedHeaders:Array<String>, ?payload:String):String {
		// ensure there is a host header
		switch req.byName(HOST) {
			case Success(_): // ok
			case Failure(_):
				if(req.url.host == null) throw 'unknown host';
				req = req.concat([new HeaderField(HOST, req.url.host.toString())]);
		}
		
		var s = '';
		inline function append(v:String) s += v + '\n';
		append(req.method);
		append(req.url.path);
		
		var params = req.url.query.toMap();
		var keys = [for(k in params.keys()) k];
		keys.sort(Reflect.compare);
		append([for(k in keys) '$k=${params.get(k).urlEncode()}'].join('&'));
		
		var headers = [for(h in req) h];
		headers.sort(function(h1, h2) return Reflect.compare(h1.name, h2.name));
		var map = new Map();
		for(h in headers) map[h.name] = if(map.exists(h.name)) map[h.name] + ',' + h.value else h.value;
		var keys = [for(k in map.keys()) (k:String)];
		append([for(k in keys) '${k}:${map[k]}'].join('\n'));
		append('');
		if(signedHeaders == null) signedHeaders = keys;
		else for(sh in signedHeaders) switch req.byName(sh) {
			case Success(_): // ok
			case Failure(e): throw e;
		}
		append(signedHeaders.join(';'));
		
		return s + (payload == null ? 'UNSIGNED-PAYLOAD' : Sha256.encode(payload));
	}

	// /**
	//  *  Used to sign the IoT endpoint URL to establish a MQTT websocket.
	//  *  @param {string} host - Our AWS IoT endpoint.
	//  *  @param {string} region - Our AWS region (us-east-1).
	//  *  @param {object} credentials - Current user's stored AWS.config.credentials object.
	// */
	// public static function getSignedUrl(config:{
	// 	protocol:String,
	// 	host:String,
	// 	region:String,
	// 	service:String,
	// 	path:String,
	// 	method:String,
	// 	credentials:Credentials,
	// }) {
	// 	var protocol = config.protocol;
	// 	var host = config.host;
	// 	var region = config.region;
	// 	var service = config.service;
	// 	var path = config.path;
	// 	var method = config.method;
	// 	var credentials = config.credentials;
		
	// 	var timezoneOffset = new Date(1970,0,1,0,0,0).getTime();
	// 	var datetime = Date.now().delta(timezoneOffset).format('%Y%m%dT%H%M%SZ');
	// 	var date = datetime.substr(0, 8);

	// 	if(path.charCodeAt(0) != '/'.code) path = '/$path';
	// 	var algorithm = 'AWS4-HMAC-SHA256';

	// 	var credentialScope = '${date}/${region}/${service}/aws4_request';
	// 	var canonicalQuerystring = 'X-Amz-Algorithm=${algorithm}';
	// 	var credentialsURI = '${credentials.accessKeyId}/${credentialScope}'.urlEncode();
	// 	canonicalQuerystring += '&X-Amz-Credential=${credentialsURI}';
	// 	canonicalQuerystring += '&X-Amz-Date=${datetime}';
	// 	canonicalQuerystring += '&X-Amz-SignedHeaders=host';

	// 	var canonicalHeaders = 'host:${host}\n';
	// 	var payloadHash = Sha256.encode('');

	// 	var canonicalRequest = method + '\n' + path + '\n' + canonicalQuerystring + '\n' + canonicalHeaders + '\nhost\n' + payloadHash;

	// 	var stringToSign = '${algorithm}\n${datetime}\n${credentialScope}\n${Sha256.encode(canonicalRequest)}';
	// 	var signingKey = createSignatureKey(credentials.secretAccessKey, date, region, service);
	// 	var signature = new Hmac(SHA256).make(signingKey, Bytes.ofString(stringToSign)).toHex();

	// 	canonicalQuerystring += '&X-Amz-Signature=${signature}';
	// 	if (credentials.sessionToken != null) {
	// 		canonicalQuerystring += '&X-Amz-Security-Token=${credentials.sessionToken.urlEncode()}';
	// 	}

	// 	var requestUrl = '${protocol}://${host}${path}?${canonicalQuerystring}';
	// 	return requestUrl;
	// };
	
	static function createSignatureKey(secretAccessKey:String, date:Date, region:String, service:String) {
		var hmac = new Hmac(SHA256);
		var kDate = hmac.make(Bytes.ofString('AWS4$secretAccessKey'), Bytes.ofString(date.format('%Y%m%d')));
		var kRegion = hmac.make(kDate,  Bytes.ofString(region));
		var kService = hmac.make(kRegion,  Bytes.ofString(service));
		var kCredentials = hmac.make(kService,  Bytes.ofString('aws4_request'));
		return kCredentials;
	}
}

// TODO: test
// http://docs.aws.amazon.com/general/latest/gr/signature-v4-test-suite.html