# AWS SigV4

AWS Signature Version 4

# Examples

To construct a URL to allow downloading an object in S3 `examplebucket` named `test.txt`
(Example from: https://docs.aws.amazon.com/AmazonS3/latest/API/sigv4-query-string-auth.html)

```haxe
var url = SigV4.presignUrl({
	request: new OutgoingRequestHeader(GET, 'https://examplebucket.s3.amazonaws.com/test.txt', []),
	region: '<region>',
	service: 's3',
	accessKeyId: '<key>',
	secretAccessKey: '<secret>',
	expiry: 86400,
});
```

To construct a IoT URL to be used with a MQTT client:

```haxe
var url = SigV4.presignUrl({
	request: new OutgoingRequestHeader(GET, 'wss://<endpoint>/mqtt', []),
	region: '<region>',
	service: 'iotdevicegateway',
	accessKeyId: '<key>',
	secretAccessKey: '<secret>',
	payload: '',
});
```