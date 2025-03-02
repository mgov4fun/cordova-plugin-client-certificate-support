/*
 Licensed to the Apache Software Foundation (ASF) under one
 or more contributor license agreements.  See the NOTICE file
 distributed with this work for additional information
 regarding copyright ownership.  The ASF licenses this file
 to you under the Apache License, Version 2.0 (the
 "License"); you may not use this file except in compliance
 with the License.  You may obtain a copy of the License at

 http://www.apache.org/licenses/LICENSE-2.0

 Unless required by applicable law or agreed to in writing,
 software distributed under the License is distributed on an
 "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 KIND, either express or implied.  See the License for the
 specific language governing permissions and limitations
 under the License.
 */

#include <sys/types.h>
#include <sys/sysctl.h>
#include "TargetConditionals.h"

#import <Cordova/CDV.h>
#import "ClientCertificate.h"

static ClientCertificate * mydelegate = NULL;

@interface ClientCertificate ()
{
    BOOL validateSslChain;
    NSString* certificatePath;
    NSString* certificatePassword;
}
@end

@implementation ClientCertificate

- (void)pluginInitialize
{
    validateSslChain = YES;

    mydelegate = self;
    
    NSLog(@"ClientCertificate native plugin started");
}

- (void)registerAuthenticationCertificate:(CDVInvokedUrlCommand*)command
{
    // certificate path and password
    NSString* path = [command argumentAtIndex:0];
    NSString* password = [command argumentAtIndex:1];

    // check certificate path
    if(![[NSFileManager defaultManager] fileExistsAtPath:path]) {
        CDVPluginResult* pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_ERROR messageAsString:[NSString stringWithFormat:@"certificate file not found: %@", path]];
        [self.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
        return;
    }

    if (![self readAndRegisterCertificateFromPath: path withPassword:password]) {
        CDVPluginResult* pluginResult =
            [CDVPluginResult resultWithStatus:CDVCommandStatus_ERROR
                              messageAsString:@"reading certificate failed."];
        [self.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
        return;
    }
    
    //Hook into WkWebView
    //Wrap the current delegate with our own so we can hook into web view events.
    WKWebView *webView = (WKWebView *)[self webView];
    self.wrappedDelegate = [webView navigationDelegate];

    [[self webViewEngine] updateWithInfo:@{
        kCDVWebViewEngineWKNavigationDelegate : self
    }];

    [self.commandDelegate sendPluginResult:[CDVPluginResult resultWithStatus:CDVCommandStatus_OK]
                                callbackId:command.callbackId];
}

- (BOOL)readAndRegisterCertificateFromPath:(NSString*)path withPassword:(NSString*)password
{
    // check certificate and password
    SecIdentityRef myIdentity;
    SecTrustRef myTrust;
    OSStatus status = extractIdentityAndTrust(path, password, &myIdentity, &myTrust);
    if(status != noErr) {
        return false;
    }

    certificatePath = path;
    certificatePassword = password;

    return true;
}

- (void)validateSslChain:(CDVInvokedUrlCommand*)command {
    validateSslChain = [command argumentAtIndex:0];
    CDVPluginResult* pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK];
    [self.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
}


OSStatus extractIdentityAndTrust(NSString *certPath, NSString *pwd, SecIdentityRef *identity, SecTrustRef *trust)
{
    OSStatus securityError = errSecSuccess;
    NSData *PKCS12Data = [[NSData alloc] initWithContentsOfFile:certPath];
    CFDataRef inPKCS12Data = (__bridge CFDataRef)PKCS12Data;
    CFStringRef passwordRef = (__bridge CFStringRef)pwd; // Password for Certificate which client have given

    const void *keys[] =   { kSecImportExportPassphrase };
    const void *values[] = { passwordRef };

    CFDictionaryRef optionsDictionary = CFDictionaryCreate(NULL, keys, values, 1, NULL, NULL);
    CFArrayRef items = CFArrayCreate(NULL, 0, 0, NULL);
    securityError = SecPKCS12Import(inPKCS12Data, optionsDictionary, &items);

    if (securityError == 0) {
        CFDictionaryRef myIdentityAndTrust = CFArrayGetValueAtIndex (items, 0);
        const void *tempIdentity = NULL;
        tempIdentity = CFDictionaryGetValue (myIdentityAndTrust, kSecImportItemIdentity);

        *identity = (SecIdentityRef)tempIdentity;

        const void *tempTrust = NULL;
        tempTrust = CFDictionaryGetValue (myIdentityAndTrust, kSecImportItemTrust);
        *trust = (SecTrustRef)tempTrust;

        SecTrustResultType trustResult;
        OSStatus status = SecTrustEvaluate(*trust, &trustResult);
        if (status == errSecSuccess) {

            // Clear app keychain
            void (^deleteAllKeysForSecClass)(CFTypeRef) = ^(CFTypeRef secClass) {
                id dict = @{(__bridge id)kSecClass: (__bridge id)secClass};
                SecItemDelete((__bridge CFDictionaryRef) dict);
            };
            deleteAllKeysForSecClass(kSecClassIdentity);

            // Persist identity to keychain
            NSMutableDictionary *secIdentityParams = [[NSMutableDictionary alloc] init];
            [secIdentityParams setObject:(__bridge id)tempIdentity forKey:(id)kSecValueRef];
            status = SecItemAdd((CFDictionaryRef) secIdentityParams, NULL);
        }
    }

    if (optionsDictionary) {
        CFRelease(optionsDictionary);
    }

    if (items)
        CFRelease(items);

    return securityError;
}

CFDataRef persistentRefForIdentity(SecIdentityRef identity)
{
    OSStatus status = errSecSuccess;

    CFTypeRef  persistent_ref = NULL;
    const void *keys[] =   { kSecReturnPersistentRef, kSecValueRef };
    const void *values[] = { kCFBooleanTrue,          identity };
    CFDictionaryRef dict = CFDictionaryCreate(NULL, keys, values,
                                              2, NULL, NULL);
    status = SecItemAdd(dict, &persistent_ref);

    if (dict)
        CFRelease(dict);

    return (CFDataRef)persistent_ref;
}

SecIdentityRef identityForPersistentRef(CFDataRef persistent_ref)
{
    CFTypeRef   identity_ref     = NULL;
    const void *keys[] =   { kSecClass, kSecReturnRef,  kSecValuePersistentRef };
    const void *values[] = { kSecClassIdentity, kCFBooleanTrue, persistent_ref };
    CFDictionaryRef dict = CFDictionaryCreate(NULL, keys, values,
                                              3, NULL, NULL);
    SecItemCopyMatching(dict, &identity_ref);

    if (dict)
        CFRelease(dict);

    return (SecIdentityRef)identity_ref;
}

+ (void)registerCertificateFromPath:(NSString*)path withPassword:(NSString*)password
{
    NSLog(@"ClientCertificate - registerCertificateFromPath with path: %@", path);

    [mydelegate readAndRegisterCertificateFromPath:path withPassword:password];
}

#pragma mark - WKNavigationDelegate implementation

- (BOOL)respondsToSelector:(SEL)aSelector
{
    if ([super respondsToSelector:aSelector]) {
        return YES;
    }
    if ([self.wrappedDelegate respondsToSelector:aSelector]) {
        return YES;
    }
    return NO;
}

- (void)forwardInvocation:(NSInvocation *)anInvocation
{
    if ([super respondsToSelector:[anInvocation selector]])
        [anInvocation invokeWithTarget:self];
    else
        [anInvocation invokeWithTarget:self.wrappedDelegate];
    
}

- (NSMethodSignature*) methodSignatureForSelector:(SEL)selector
{
    NSObject *delegateForResonse = [super respondsToSelector:selector] ? self : self.wrappedDelegate;
    return [delegateForResonse respondsToSelector:selector] ? [delegateForResonse methodSignatureForSelector:selector] : nil;

}

- (void)webView:(WKWebView *)theWebView didReceiveAuthenticationChallenge:(NSURLAuthenticationChallenge *)challenge completionHandler:(void (^)(NSURLSessionAuthChallengeDisposition disposition, NSURLCredential * _Nullable credential))completionHandler
{
    NSString *authenticationMethod = [[challenge protectionSpace] authenticationMethod];
        NSURLCredential *credential = nil;
    
    NSLog(@"ClientCertificate - didReceiveAuthenticationChallenge with authenticationMethod: %@", authenticationMethod);
    
    if ([authenticationMethod isEqualToString:NSURLAuthenticationMethodClientCertificate]){
            SecIdentityRef myIdentity = NULL;
            
            NSMutableDictionary *query = [NSMutableDictionary dictionaryWithObjectsAndKeys:
                                          (__bridge id)kSecClass, (__bridge id)kSecClass,
                                          (__bridge id)kCFBooleanTrue, (__bridge id)kSecReturnRef,
                                          (__bridge id)kSecMatchLimitOne, (__bridge id)kSecMatchLimit,
                                          nil];

            NSArray *secItemClasses = [NSArray arrayWithObjects:
                                       (__bridge id)kSecClassIdentity,
                                       nil];

            for (id secItemClass in secItemClasses) {
                [query setObject:secItemClass forKey:(__bridge id)kSecClass];

                CFTypeRef result = NULL;
                SecItemCopyMatching((__bridge CFDictionaryRef)query, &result);
                if(result != NULL) {
                    myIdentity = (SecIdentityRef)result;
                }
            }
            
            SecCertificateRef myCertificate;
            if(myIdentity != NULL) {
                SecIdentityCopyCertificate(myIdentity, &myCertificate);
                const void *certs[] = { myCertificate };
                CFArrayRef certsArray = CFArrayCreate(NULL, certs, 1, NULL);
                credential = [NSURLCredential credentialWithIdentity:myIdentity certificates:(__bridge NSArray*)certsArray persistence:NSURLCredentialPersistencePermanent];
            }
            
            completionHandler(NSURLSessionAuthChallengeUseCredential, credential);
        } else if([authenticationMethod isEqualToString:NSURLAuthenticationMethodServerTrust])
        {
            SecTrustRef secTrustRef = challenge.protectionSpace.serverTrust;
            if (secTrustRef != NULL)
            {
                SecTrustResultType result;
                OSErr er = SecTrustEvaluate(secTrustRef, &result);
                if (er != noErr){
                    NSLog(@"error");
                }
          
                switch ( result )
                {
                    case kSecTrustResultProceed:
                        NSLog(@"ClientCertificate - kSecTrustResultProceed");
                        completionHandler(NSURLSessionAuthChallengePerformDefaultHandling, nil);
                        break;
                    case kSecTrustResultUnspecified: // called 2nd
                        NSLog(@"ClientCertificate - kSecTrustResultUnspecified");
                        completionHandler(NSURLSessionAuthChallengeUseCredential, [NSURLCredential credentialForTrust:secTrustRef]);
                        break;
                    case kSecTrustResultRecoverableTrustFailure:
                        NSLog(@"ClientCertificate - kSecTrustResultRecoverableTrustFailure");
                        completionHandler(NSURLSessionAuthChallengeUseCredential, [NSURLCredential credentialForTrust:secTrustRef]);
                        break;
                    default:
                        NSLog(@"ClientCertificate - SecTrustResultType not treated: %u", result);
                }
            }
        }else {
            NSLog(@"ClientCertificate - Unknown authenticationMethod: %@", authenticationMethod);
        }
}

@end
