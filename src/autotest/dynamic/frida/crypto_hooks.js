/* autotest crypto hooks (M4.2). READ-ONLY: observes args, never alters behavior.
 * Each hit logs one line:  AUTOTEST_HOOK <json>  (consumed by dynamic analyzers).
 */
'use strict';

function b2hex(arr) {
  try {
    var out = '';
    for (var i = 0; i < arr.length; i++) {
      var h = (arr[i] & 0xff).toString(16);
      out += (h.length === 1 ? '0' : '') + h;
    }
    return out.slice(0, 128);
  } catch (e) { return '?'; }
}

function emit(obj) {
  try { console.log('AUTOTEST_HOOK ' + JSON.stringify(obj)); } catch (e) { /* ignore */ }
}

function hook(cls, method, overloads, onHit) {
  try {
    var C = Java.use(cls);
    overloads.forEach(function (sig) {
      C[method].overload(sig).implementation = function () {
        try { emit(onHit(Array.prototype.slice.call(arguments))); } catch (e) { /* ignore */ }
        return this[method].apply(this, arguments);
      };
    });
  } catch (e) { /* class/method absent on this target */ }
}

Java.perform(function () {
  hook('javax.crypto.Cipher', 'getInstance', ['java.lang.String'], function (a) {
    return { hook: 'cipher.getInstance', transformation: String(a[0]) };
  });
  hook('javax.crypto.Cipher', 'init', ['int', 'java.security.Key'], function (a) {
    return { hook: 'cipher.init', opmode: a[0], keyAlg: String(a[1].getAlgorithm()) };
  });
  hook('javax.crypto.Cipher', 'init',
    ['int', 'java.security.Key', 'java.security.spec.AlgorithmParameterSpec'],
    function (a) {
      var iv = '';
      try { iv = b2hex(a[2].getIV()); } catch (e) { iv = '?'; }
      return { hook: 'cipher.init', opmode: a[0], keyAlg: String(a[1].getAlgorithm()), iv: iv };
    });
  hook('java.security.SecureRandom', 'setSeed', ['byte[]'], function (a) {
    return { hook: 'securerandom.setSeed', seed: b2hex(a[0]) };
  });
  hook('java.security.SecureRandom', 'setSeed', ['long'], function (a) {
    return { hook: 'securerandom.setSeed', seedLong: String(a[0]) };
  });
  hook('java.security.MessageDigest', 'getInstance', ['java.lang.String'], function (a) {
    return { hook: 'digest.getInstance', algorithm: String(a[0]) };
  });
  hook('javax.crypto.spec.SecretKeySpec', '$init', ['[B', 'java.lang.String'], function (a) {
    return { hook: 'secretkeyspec.init', algorithm: String(a[1]), keyLen: a[0].length };
  });
});
