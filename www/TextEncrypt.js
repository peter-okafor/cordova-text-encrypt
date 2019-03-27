var argscheck = require('cordova/argscheck'),
    exec = require('cordova/exec');

var textEncryption = {};

textEncryption.encrypt = function(key, text, successCallback, failureCallback) {
	cordova.exec( successCallback, failureCallback, 'TextEncrypt', 'encrypt', [key, text] );
};
textEncryption.decrypt = function(key, text, successCallback, failureCallback) {
	cordova.exec( successCallback, failureCallback, 'TextEncrypt', 'decrypt', [key, text] );
};

module.exports = textEncryption;
