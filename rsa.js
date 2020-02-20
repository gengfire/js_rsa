import JSEncrypt from 'jsencrypt';

const int2char = (n) => '0123456789abcdefghijklmnopqrstuvwxyz'.charAt(n);

// 二进制字节转base64
var b64map = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
var b64pad = '=';
const hex2b64 = (h) => {
  var i;
  var c;
  var ret = '';
  for (i = 0; i + 3 <= h.length; i += 3) {
    c = parseInt(h.substring(i, i + 3), 16);
    ret += b64map.charAt(c >> 6) + b64map.charAt(c & 63);
  }
  if (i + 1 === h.length) {
    c = parseInt(h.substring(i, i + 1), 16);
    ret += b64map.charAt(c << 2);
  } else if (i + 2 === h.length) {
    c = parseInt(h.substring(i, i + 2), 16);
    ret += b64map.charAt(c >> 2) + b64map.charAt((c & 3) << 4);
  }
  while ((ret.length & 3) > 0) {
    ret += b64pad;
  }
  return ret;
};
// convert a base64 string to hex
const b64tohex = (s) => {
  var ret = '';
  var i;
  var k = 0;
  var slop = 0;
  for (i = 0; i < s.length; ++i) {
    if (s.charAt(i) === b64pad) {
      break;
    }
    const v = b64map.indexOf(s.charAt(i));
    if (v < 0) {
      continue;
    }
    if (k === 0) {
      ret += int2char(v >> 2);
      slop = v & 3;
      k = 1;
    } else if (k === 1) {
      ret += int2char((slop << 2) | (v >> 4));
      slop = v & 0xf;
      k = 2;
    } else if (k === 2) {
      ret += int2char(slop);
      ret += int2char(v >> 2);
      slop = v & 3;
      k = 3;
    } else {
      ret += int2char((slop << 2) | (v >> 4));
      ret += int2char(v & 0xf);
      k = 0;
    }
  }
  if (k === 1) {
    ret += int2char(slop << 2);
  }
  return ret;
};

// 获取字符占位字节数
const strByteSize = (str) => {
  const charCode = str.charCodeAt(0);
  if (charCode <= 0x007f) {
    return 1;
  } else if (charCode <= 0x07ff) {
    return 2;
  } else if (charCode <= 0xffff) {
    return 3;
  } else {
    return 4;
  }
};
// 字符串分段
const strChunk = (str, splitLen) => {
  const maxByteLen = splitLen || 117;

  const sourceBlock = [];
  let blockTmp = '';
  let size = 0;
  let totalSize = 0;
  str.split('').forEach((text) => {
    const textByte = strByteSize(text);
    totalSize += textByte;
    // 占位字节总和小于117都算一组
    if (size < maxByteLen - textByte) {
      size += textByte;
      blockTmp += text;
    } else {
      // 暂存上一组
      sourceBlock.push(blockTmp);
      // 并新建一组
      blockTmp = text;
      size = textByte;
    }
  });
  // 如果无需分段
  if (totalSize < maxByteLen) sourceBlock.push(blockTmp);
  return sourceBlock;
};
// 分段加密
JSEncrypt.prototype.encryptLong = function(str) {
  const k = this.key;
  // k.n.bitLength() 1024
  // maxLength 117
  const maxLength = (((k.n.bitLength() + 7) >> 3) - 11);

  const ltArr = strChunk(str, maxLength);
  let hexAll = '';
  ltArr.forEach((entry) => {
    const hexTmp = k.encrypt(entry);
    hexAll += hexTmp;
  });
  return hex2b64(hexAll);
};

JSEncrypt.prototype.decryptLong = function(string) {
  const k = this.getKey();
  // k.n.bitLength() 1024
  // maxLength 128
  try {
    const decryptHex = b64tohex(string);

    // 原文小于117的密文都是补齐到256,所以分段的密文只可能是256的倍数
    // 遂一律按256分组
    // const inputLen = decryptHex.length;
    let ct = '';
    const lt = decryptHex.match(/.{1,256}/g);
    lt.forEach((entry) => {
      const t1 = k.decrypt(entry);
      ct += t1;
    });
    return ct;
  } catch (ex) {
    return false;
  }
};



// DEMO：
// Encrypt with the public key...
const publicKey = '-----BEGIN PUBLIC KEY----- AAAAA -----END PUBLIC KEY-----';
const privateKey = '-----BEGIN PRIVATE KEY----- AAAAA -----END PRIVATE KEY-----';

export const encrypt = (source) => {
  const jsEncrypt = new JSEncrypt();
  jsEncrypt.setPublicKey(publicKey);

  return jsEncrypt.encryptLong(source);
};

// Decrypt with the private key...
export const decrypt = (encrypted) => {
  const jsEncrypt = new JSEncrypt();
  jsEncrypt.setPrivateKey(privateKey);

  return jsEncrypt.decryptLong(encrypted);
};

export const emojiEncode = (txtStr) => {
  const emojiReg = [
    '\ud83c[\udf00-\udfff]',
    '\ud83d[\udc00-\ude4f]',
    '\ud83d[\ude80-\udeff]'
  ];
  return txtStr.replace(new RegExp(emojiReg.join('|'), 'g'), re => encodeURIComponent(re));
};

