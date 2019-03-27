#import <Foundation/Foundation.h>
#import <Cordova/CDVPlugin.h>

@interface TextEncrypt : CDVPlugin

@property(nonatomic, strong) NSString* callbackID;

- (void)encrypt:(CDVInvokedUrlCommand*)command;
- (void)decrypt:(CDVInvokedUrlCommand*)command;

@end
