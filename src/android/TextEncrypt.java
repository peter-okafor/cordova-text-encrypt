package com.niftyfissions;

import android.util.Log;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import org.apache.cordova.CallbackContext;
import org.apache.cordova.CordovaPlugin;
import org.apache.cordova.PluginResult;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;
import javax.crypto.Cipher;
import android.util.Base64;
import android.telephony.TelephonyManager;
import android.content.pm.PackageManager;
import android.content.SharedPreferences;
import org.apache.cordova.CordovaInterface;
import org.apache.cordova.CordovaWebView;

public class TextEncrypt
extends CordovaPlugin {
    private static final String LOGTAG = "TextEncrypt";

    private static final String ACTION_ENCRYPT = "encrypt";
    private static final String ACTION_DECRYPT = "decrypt";
    private CallbackContext callbackContext;

    public void initialize(CordovaInterface cordova, CordovaWebView webView) {
        super.initialize(cordova, webView);
        Log.v(LOGTAG, "Init TextEncrypt");
    }

    public boolean execute(String action, JSONArray inputs, CallbackContext callbackContext) throws JSONException {
        this.callbackContext = callbackContext;
        PluginResult result = null;
        if (ACTION_ENCRYPT.equals(action)) {
            String theKey = inputs.getString(0);
            String theText = inputs.getString(1);
            result = this.encrypt(theKey, theText);
        } else if (ACTION_DECRYPT.equals(action)) {
            String theKey = inputs.getString(0);
            String theText = inputs.getString(1);
            result = this.decrypt(theKey, theText);
        } else {
            Log.d(LOGTAG, String.format("Invalid action passed: %s", action));
            result = new PluginResult(PluginResult.Status.INVALID_ACTION);
        }
        callbackContext.sendPluginResult(result);
        return true;
    }

    public PluginResult encrypt(String key, String value) {
        try {
            String initVector = this.generateIVValue();
            IvParameterSpec iv = new IvParameterSpec(initVector.getBytes());
            SecretKeySpec skeySpec = new SecretKeySpec(key.getBytes(), "AES");

            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
            cipher.init(Cipher.ENCRYPT_MODE, skeySpec, iv);

            byte[] encrypted = cipher.doFinal(value.getBytes());
            String encVal = Base64.encodeToString(encrypted, Base64.NO_WRAP);
            String encString = injectIVInEncryptedString(encVal, initVector);
            return new PluginResult(PluginResult.Status.OK, encString);
        } catch (Exception ex) {
            ex.printStackTrace();
        }
        return new PluginResult(PluginResult.Status.ERROR, "Error performing encryption");
    }

    public PluginResult decrypt(String key, String encrypted) {
        try {
            String[] dy = this.splitDataAndIVFromEncryptedString(encrypted, 16);
            IvParameterSpec iv = new IvParameterSpec(dy[1].getBytes());
            SecretKeySpec skeySpec = new SecretKeySpec(key.getBytes(), "AES");

            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
            cipher.init(Cipher.DECRYPT_MODE, skeySpec, iv);
            byte[] original = cipher.doFinal(Base64.decode(dy[0], Base64.NO_WRAP));

            return new PluginResult(PluginResult.Status.OK, new String(original));
        } catch (Exception ex) {
            ex.printStackTrace();
        }

        return new PluginResult(PluginResult.Status.ERROR, "Error performing encryption");
    }

    public String injectIVInEncryptedString(String encrypted, String iv) {
        String b = encrypted.substring(encrypted.length() - 2, encrypted.length());
        String a = encrypted.substring(0, encrypted.length() - 2);

        return a + iv + b;
    }

    public String[] splitDataAndIVFromEncryptedString(String encryptedString, int keySpecSize){
        int bEndIndex = encryptedString.length();
        int bStartIndex = bEndIndex - 2;
        String b = encryptedString.substring(bStartIndex, bEndIndex);

        int aEndIndex = encryptedString.length() - (keySpecSize + 2);
        String a = encryptedString.substring(0, aEndIndex);

        int ivStartIndex = bStartIndex - keySpecSize;
        String iv = encryptedString.substring(ivStartIndex, bStartIndex);

        String message = a + b;
        String [] dx = {message, iv};
        return dx;
    }

    private String generateIVValue() {
        SecureRandom random = new SecureRandom();
        byte bytes[] = new byte[16];
        random.nextBytes(bytes);
        String s = Base64.encodeToString(bytes, Base64.NO_WRAP);
        return s.substring(0, 16);
    }
    //

}
