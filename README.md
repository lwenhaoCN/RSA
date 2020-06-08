## JS RSA 公钥解密

### 需求
后台使用私钥加密数据，然后前端使用公钥解密，也不知道怎么搞出来的这种需求，感觉很不符合逻辑。我对RSA的理解为：公钥负责加密，私钥负责解密。签名的话，私钥负责签名，公钥负责验证。例如：既然是加密，那肯定是不希望别人知道我的消息，所以只有我才能解密，所以可得出公钥负责加密，私钥负责解密；同理，既然是签名，那肯定是不希望有人冒充我发消息，只有我才能发布这个签名，所以可得出私钥负责签名，公钥负责验证。

### 参考
参考1： [jsencrypt.js](https://github.com/travist/jsencrypt "jsencrypt.js") 

参考2： [How to decrypt the encrypted string by private key with public key?](https://github.com/kjur/jsrsasign/issues/344?utm_source=hacpai.com "How to decrypt the encrypted string by private key with public key?")

参考3：[rsasign-1.2.js](https://github.com/kjur/jsrsasign/blob/master/src/rsasign-1.2.js#L234 "rsasign-1.2.js")

### 实现
#####  1. 修改 ` RSAKey.prototype.decrypt` 中 `this.doPrivate(c)` 为 `this.doPublic(c);`

	RSAKey.prototype.decrypt = function (ctext) {
		var c = parseBigInt(ctext, 16);
		var m = this.doPublic(c);
		//var m = this.doPrivate(c);
		if (m == null) {
			return null;
		}
		return pkcs1unpad2(m, (this.n.bitLength() + 7) >> 3);
	};


#####  2. 修改 `pkcs1unpad2`
	 function pkcs1unpad2(d, n) {
	 	var b = d.toByteArray();
		var i = 0;
		while (i < b.length && b[i] == 0) {
			++i;
		}
		//注释即可
		// if (b.length - i != n - 1 || b[i] != 2) {
		//     return null;
		// }
		++i;
		while (b[i] != 0) {
			if (++i >= b.length) {
				return null;
			}
		}
		var ret = "";
		while (++i < b.length) {
			var c = b[i] & 255;
			if (c < 128) { // utf-8 decode
				ret += String.fromCharCode(c);
			} else if ((c > 191) && (c < 224)) {
				ret += String.fromCharCode(((c & 31) << 6) | (b[i + 1] & 63));
				++i;
			} else {
				ret += String.fromCharCode(((c & 15) << 12) | ((b[i + 1] & 63) << 6) | (b[i + 2] & 63));
				i += 2;
			}
		}
		return ret;
	}

##### 3. 调用
	var verify = new JSEncrypt();
	//替换为公钥，格式为：-----BEGIN PUBLIC KEY----- 公钥 -----END PUBLIC KEY-----
	verify.setPublicKey($('#pubkey').val());
	//使用私钥加密后的数据
	var verified = verify.decrypt("Y/f5VqHyS6+9uVZIQLRFbLtNNvnYnrEOFRMCg0FmeojihSILNyrIerh5zYoVbRm9S16K65shz1VW5s/qQxk4hDmQ/cDo3yNdGhzS62XWN9f6rNIRk4pANSqrlt+3/kgooGlPcVRWGuNM2wX2WOJw0OgelZfFIbu0dIHlP8ohZ7w=");
	console.log('解密后数据：', verified);

### 源码

[RSA公钥解密_地址1](http://git.lwenhao.com/lwenhao/RSA "RSA公钥解密_地址1")

[RSA公钥解密_地址2](https://github.com/lwenhaoCN/RSA "RSA公钥解密__地址2")
