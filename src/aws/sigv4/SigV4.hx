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
		var signedHeaders = [for(h in options.request) h.name];
		if(signedHeaders.indexOf('host') == -1) signedHeaders.push('host');
		
		var query = (options.request.url.query == null ? '' : options.request.url.query + '&') 
			+  'X-Amz-Algorithm=$ALGORITHM'
			+ '&X-Amz-Credential=${StringTools.urlEncode(options.accessKeyId + '/' + scope)}'
			+ '&X-Amz-Date=${date.format('%Y%m%dT%H%M%SZ')}'
			+ (options.expiry == null ? '' : '&X-Amz-Expires=${options.expiry}')
			+ '&X-Amz-SignedHeaders=${signedHeaders.join(';')}'
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
			+ (options.sessionToken == null ? '' : '&X-Amz-Security-Token=${options.sessionToken.urlEncode()}')
		);
	}
	
	public static function signRequest(options:{
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
			
		var request = options.request.concat({
			var headers = [
				new HeaderField('X-Amz-Date', date.format('%Y%m%dT%H%M%SZ')),
			];
			if(options.expiry != null)
				headers.push(new HeaderField('X-Amz-Expiry', Std.string(options.expiry)));
			switch options.request.byName(HOST) {
				case Success(_): // ok
				case Failure(_): headers.push(new HeaderField(HOST, options.request.url.host.toString()));
			}
			if(options.service == 's3')
				headers.push(new HeaderField('X-Amz-Content-SHA256', createPayloadHash(options.payload)));
			
			headers;
		});
		
		var signedHeaders = [for(h in request) h.name];
		signedHeaders.sort(Reflect.compare);
		
		var canonicalRequest = createCanonicalRequest(request, signedHeaders, options.payload);
		var stringToSign = createStringToSign(date, scope, canonicalRequest);
		var signingKey = createSignatureKey(options.secretAccessKey, date, options.region, options.service);
		var signature = createSignature(signingKey, stringToSign);
		
		return request.concat([new HeaderField(AUTHORIZATION, '$ALGORITHM Credential=${options.accessKeyId}/$scope, SignedHeaders=${signedHeaders.join(';')}, Signature=$signature')]);
	}
	
	static function replaceQuery(url:Url, query:String) {
		return Url.make({
			path: url.path,
			query: query,
			hosts: [for(host in url.hosts) host],
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
		append([for(k in keys) '$k=${StringTools.urlEncode(params.get(k))}'].join('&'));
		
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
		
		return s + createPayloadHash(payload);
	}
	
	static function createPayloadHash(payload:String) {
		return payload == null ? 'UNSIGNED-PAYLOAD' : Sha256.encode(payload);
	}

	static function createSignatureKey(secretAccessKey:String, date:Date, region:String, service:String) {
		var hmac = new Hmac(SHA256);
		var kDate = hmac.make(Bytes.ofString('AWS4$secretAccessKey'), Bytes.ofString(date.format('%Y%m%d')));
		var kRegion = hmac.make(kDate,  Bytes.ofString(region));
		var kService = hmac.make(kRegion,  Bytes.ofString(service));
		var kCredentials = hmac.make(kService,  Bytes.ofString('aws4_request'));
		return kCredentials;
	}
	
}
