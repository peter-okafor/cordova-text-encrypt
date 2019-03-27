#import "TextEncrypt.h"
#import <CommonCrypto/CommonCryptor.h>
#import <CommonCrypto/CommonKeyDerivation.h>
#import <Security/Security.h>

@interface TextEncrypt ()

@end

@implementation TextEncrypt

- (void) encrypt: (CDVInvokedUrlCommand*)command{
    self.callbackID = command.callbackId;
    NSData *key = [[command.arguments objectAtIndex:0] dataUsingEncoding:NSUTF8StringEncoding];
    NSData *data = [[command.arguments objectAtIndex:1] dataUsingEncoding:NSUTF8StringEncoding];
    NSString* iv = [self generateIV];
    NSData* success = [self crypt:data withKey:key withIV:iv withOp:kCCEncrypt];
    if (success==NO){
        CDVPluginResult* pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_ERROR messageAsString:@"Error encrypting"];
        [self.commandDelegate sendPluginResult:pluginResult callbackId:self.callbackID];
    }
    else {
        NSString* ivinjected = [self injectIV:iv InEncryptedData:[success base64EncodedStringWithOptions:0]];
        CDVPluginResult* pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK messageAsString:ivinjected];
        [self.commandDelegate sendPluginResult:pluginResult callbackId:self.callbackID];
    }
}

- (void) decrypt: (CDVInvokedUrlCommand*)command{
    self.callbackID = command.callbackId;
    NSArray* encdata = [self splitDataAndIVFromEncryptedString:[command.arguments objectAtIndex:1] withKeySize:16];
    NSData *key = [[command.arguments objectAtIndex:0] dataUsingEncoding:NSUTF8StringEncoding];
    NSData *data = [[NSData alloc] initWithBase64EncodedString:[encdata objectAtIndex:0] options:0];
    NSString* iv = [encdata objectAtIndex:1];
    NSData* success = [self crypt:data withKey:key withIV:iv withOp:kCCDecrypt];
    if (success==NO){
        CDVPluginResult* pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_ERROR messageAsString:@"Error decrypting"];
        [self.commandDelegate sendPluginResult:pluginResult callbackId:self.callbackID];
    }
    else {
        NSString* decString = [[NSString alloc] initWithData:success encoding:NSUTF8StringEncoding];
        CDVPluginResult* pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK messageAsString:decString];
        [self.commandDelegate sendPluginResult:pluginResult callbackId:self.callbackID];
    }
}

- (NSData*) crypt: (NSData*) theData withKey: (NSData*) key withIV:(NSString*) theiv withOp: (CCOperation) theOp{
    size_t outLength;
    NSMutableData *cipherData = [NSMutableData dataWithLength:theData.length + kCCBlockSizeAES128];
    if (theiv.length!=kCCBlockSizeAES128) {
        NSLog(@"IV length not 16");
        return nil;
    }
    NSData  *iv = [theiv dataUsingEncoding:NSUTF8StringEncoding];

    //Create Cryptor
    CCCryptorStatus  create = CCCrypt(theOp,
                                      kCCAlgorithmAES128,
                                      kCCOptionPKCS7Padding,
                                      key.bytes,
                                      key.length,
                                      iv.bytes,
                                      theData.bytes,
                                      theData.length,
                                      cipherData.mutableBytes,
                                      cipherData.length,
                                      &outLength
                                      );
    if (create == kCCSuccess){
        NSData* adata = [[NSData alloc] initWithBytes:cipherData.mutableBytes length:outLength];
        return adata;
    }
    return nil;
}

- (NSString*) injectIV: (NSString*) iv InEncryptedData: (NSString*) encstring{
    NSInteger splitpoint = encstring.length - 2;
    NSString* a = [encstring substringWithRange:NSMakeRange(0, splitpoint)];
    NSString* b = [encstring substringWithRange:NSMakeRange(splitpoint, encstring.length - splitpoint)];
    NSString *concat = [NSString stringWithFormat: @"%@%@", a, iv];
    NSString *finalconcat = [NSString stringWithFormat: @"%@%@", concat, b];
    return finalconcat;
}

- (NSArray*) splitDataAndIVFromEncryptedString: (NSString*) joineddata withKeySize: (NSInteger) keysize {
    NSInteger splitpoint = joineddata.length - 2;
    NSInteger asize = splitpoint - keysize;
    NSString* b = [joineddata substringWithRange:NSMakeRange(splitpoint, joineddata.length - splitpoint)];
    NSString* a = [joineddata substringWithRange:NSMakeRange(0, asize)];
    NSString* iv = [joineddata substringWithRange:NSMakeRange(asize, keysize)];
    NSString *message = [NSString stringWithFormat: @"%@%@", a, b];
    NSArray *dx;
    dx = [NSArray arrayWithObjects: message, iv, nil];
    return dx;
}


- (NSString*) generateIV{
    int ivLength   = kCCBlockSizeAES128;
    NSMutableData *iv = [NSMutableData dataWithLength:ivLength];
    int status = SecRandomCopyBytes(kSecRandomDefault, ivLength, iv.mutableBytes);
    if (status != 0) {
        NSLog(@"ERROR generating iv");
        return nil;
    }
    NSString* theiv = [[iv base64EncodedStringWithOptions:0] substringWithRange:NSMakeRange(0, 16)];
    return theiv;
}

@end
