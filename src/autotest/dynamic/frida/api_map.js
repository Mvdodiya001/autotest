/* autotest sensitive-API map hooks (M4.2). READ-ONLY: logs usage, never blocks.
 * Line format:  AUTOTEST_HOOK {"hook":"api.use","api":"<class>.<method>"}
 */
'use strict';

function emit(obj) {
  try { console.log('AUTOTEST_HOOK ' + JSON.stringify(obj)); } catch (e) { /* ignore */ }
}

function watch(cls, methods) {
  try {
    var C = Java.use(cls);
    methods.forEach(function (m) {
      C[m].overloads.forEach(function (ov) {
        ov.implementation = function () {
          emit({ hook: 'api.use', api: cls + '.' + m });
          return ov.apply(this, arguments);
        };
      });
    });
  } catch (e) { /* absent on this target */ }
}

Java.perform(function () {
  watch('android.location.LocationManager', ['requestLocationUpdates', 'getLastKnownLocation']);
  watch('android.hardware.Camera', ['open', 'takePicture']);
  watch('android.hardware.camera2.CameraManager', ['openCamera']);
  watch('android.telephony.TelephonyManager', ['getDeviceId', 'getImei', 'getSubscriberId']);
  watch('android.telephony.SmsManager', ['sendTextMessage', 'sendMultipartTextMessage']);
  watch('android.content.ContentResolver', ['query']);
  watch('android.media.MediaRecorder', ['start']);
  watch('android.net.wifi.WifiManager', ['getConnectionInfo']);
});
