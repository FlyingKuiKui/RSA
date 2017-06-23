//
//  ViewController.m
//  RSA
//
//  Created by 王盛魁 on 2017/6/23.
//  Copyright © 2017年 WangShengKui. All rights reserved.
//

#import "EncryptTool.h"
/*
  基于Security.framework的RSA加密
 */
@interface EncryptTool (){
    SecKeyRef _publicKey; // 公钥
    SecKeyRef _privateKey;// 私钥
}
@property (nonatomic,copy) NSString *derFilePath; // cer文件路径
@property (nonatomic,copy) NSString *p12FilePath; // p12文件路径
@property (nonatomic,copy) NSString *p12Password; //p12文件密码
@end


@implementation EncryptTool
#pragma mark - 从der证书文件中获取公钥
/**
 *  获取公钥
 *
 *  @return
 */
- (SecKeyRef)getPublicKey {
    if (!_publicKey) {
        [self loadPublicKeyFromFile:self.derFilePath];
    }
    return _publicKey;
}

/**
 *  通过文件路径加载公钥
 *
 *  @param derFilePath 公钥文件路径
 */
- (void)loadPublicKeyFromFile:(NSString *)derFilePath {
    if (derFilePath == nil) {
        return;
    }
    self.derFilePath = derFilePath;
    NSData *cerData = [[NSData alloc] initWithContentsOfFile:derFilePath];
    [self loadPublicKeyFromData:cerData];
}

/**
 *  通过NSData加载公钥
 *  （此方法可用于将公钥配置在服务端，以Base64字符串传到移动端来加载）
 *  @param derData 公钥data
 */
- (void)loadPublicKeyFromData:(NSData *)cerData {
    _publicKey = [self getPublicKeyRefrenceFromeData:cerData];
}

#pragma mark - Private Methods

/**
 *  （私有方法）从data获取公钥
 *
 *  @param certData data
 *
 *  @return 公钥
 */
- (SecKeyRef)getPublicKeyRefrenceFromeData:(NSData *)certData {
    SecKeyRef publicKeyRef = NULL;
    CFDataRef myCertData = (__bridge CFDataRef)certData;
    SecCertificateRef cert = SecCertificateCreateWithData(NULL, (CFDataRef)myCertData);
    if (cert == nil) {
        NSLog(@"Can not read certificate from %@", self.derFilePath);
        return nil;
    }
    SecPolicyRef policy = SecPolicyCreateBasicX509();
    SecCertificateRef certArray[1] = {cert};
    CFArrayRef myCerts = CFArrayCreate(NULL, (void *)certArray,1, NULL);
    SecTrustRef trust;
    OSStatus status = SecTrustCreateWithCertificates(myCerts, policy, &trust);
    if (status != noErr) {
        NSLog(@"SecTrustCreateWithCertificates fail. Error Code: %d", (int)status);
        CFRelease(cert);
        CFRelease(policy);
        CFRelease(myCerts);
        return nil;
    }
    SecTrustResultType trustResult;
    status = SecTrustEvaluate(trust, &trustResult);
    if (status != noErr) {
        NSLog(@"SecTrustEvaluate fail. Error Code: %d", (int)status);
        CFRelease(cert);
        CFRelease(policy);
        CFRelease(trust);
        CFRelease(myCerts);
        return nil;
    }
    publicKeyRef = SecTrustCopyPublicKey(trust);
    
    CFRelease(cert);
    CFRelease(policy);
    CFRelease(trust);
    CFRelease(myCerts);
    
    return publicKeyRef;
}

#pragma mark - 从p12文件中获取私钥

/**
 *  获取私钥
 *
 *  @return
 */
- (SecKeyRef)getPrivateKey {
    if (!_privateKey) {
        [self loadPrivateKeyFromFile:self.p12FilePath password:self.p12Password];
    }
    return _privateKey;
}

/**
 *  通过文件路径加载私钥
 *
 *  @param p12FilePath 私钥文件路径
 *  @param p12Password 私钥密码
 */
- (void)loadPrivateKeyFromFile:(NSString*)p12FilePath password:(NSString*)p12Password {
    if (p12FilePath == nil) {
        return;
    }
    self.p12FilePath = p12FilePath;
    self.p12Password = p12Password;
    NSData *p12Data = [NSData dataWithContentsOfFile:p12FilePath];
    [self loadPrivateKeyFromData: p12Data password:p12Password];
}

/**
 *  通过NSData加载私钥
 *
 *  @param p12Data     私钥data
 *  @param p12Password 私钥密码
 */
- (void)loadPrivateKeyFromData:(NSData*)p12Data password:(NSString*)p12Password {
    _privateKey = [self getPrivateKeyRefrenceFromData:p12Data password:p12Password];
}

/**
 *  （私有方法）从data获取私钥
 *
 *  @param derData data
 *
 *  @return 私钥
 */
- (SecKeyRef)getPrivateKeyRefrenceFromData:(NSData*)p12Data password:(NSString*)password {
    SecKeyRef privateKeyRef = NULL;
    NSMutableDictionary * options = [[NSMutableDictionary alloc] init];
    [options setObject: password forKey:(__bridge id)kSecImportExportPassphrase];
    CFArrayRef items = CFArrayCreate(NULL, 0, 0, NULL);
    OSStatus securityError = SecPKCS12Import((__bridge CFDataRef) p12Data, (__bridge CFDictionaryRef)options, &items);
    if (securityError == noErr && CFArrayGetCount(items) > 0) {
        CFDictionaryRef identityDict = CFArrayGetValueAtIndex(items, 0);
        SecIdentityRef identityApp = (SecIdentityRef)CFDictionaryGetValue(identityDict, kSecImportItemIdentity);
        securityError = SecIdentityCopyPrivateKey(identityApp, &privateKeyRef);
        if (securityError != noErr) {
            privateKeyRef = NULL;
        }
    }
    CFRelease(items);
    
    return privateKeyRef;
}
#pragma mark - 加密
/**
 *  字符串加密
 *
 *  @param string 明文
 *
 *  @return 密文（base64防止乱码）
 */
- (NSString *)rsaEncryptString:(NSString *)string {
    NSData *data = [string dataUsingEncoding:NSUTF8StringEncoding];
    NSData *encryptedData = [self rsaEncryptData: data];
    NSString *base64EncryptedString = [encryptedData base64EncodedStringWithOptions:NSDataBase64Encoding64CharacterLineLength];
    return base64EncryptedString;
}

// 加密的大小受限于SecKeyEncrypt函数，SecKeyEncrypt要求明文和密钥的长度一致，如果要加密更长的内容，需要把内容按密钥长度分成多份，然后多次调用SecKeyEncrypt来实现
- (NSData*)rsaEncryptData:(NSData*)data {
    SecKeyRef key = [self getPublicKey];
    
    const uint8_t *srcbuf = (const uint8_t *)[data bytes];
    size_t srclen = (size_t)data.length;
    
    size_t block_size = SecKeyGetBlockSize(key) * sizeof(uint8_t);
    void *outbuf = malloc(block_size);
    size_t src_block_size = block_size - 11;
    
    NSMutableData *ret = [[NSMutableData alloc] init];
    for(int idx = 0; idx < srclen; idx += src_block_size){
        //        NSLog(@"%d/%d block_size: %d", idx, (int)srclen, (int)block_size);
        size_t data_len = srclen - idx;
        if (data_len > src_block_size) {
            data_len = src_block_size;
        }
        
        size_t outlen = block_size;
        OSStatus status = noErr;
        status = SecKeyEncrypt(key,
                               kSecPaddingPKCS1,
                               srcbuf + idx,
                               data_len,
                               outbuf,
                               &outlen
                               );
        if (status != 0) {//0为成功
            NSLog(@"SecKeyEncrypt fail. Error Code: %d", (int)status);
            ret = nil;
            break;
        }else{
            [ret appendBytes:outbuf length:outlen];
        }
    }
    
    free(outbuf);
    return ret;
}
#pragma mark - 解密
/**
 *  解密字符串
 *
 *  @param string 密文
 *
 *  @return 明文
 */
- (NSString *)rsaDecryptString:(NSString*)string {
    
    NSData *data = [[NSData alloc] initWithBase64EncodedString:string options:NSDataBase64DecodingIgnoreUnknownCharacters];
    NSData *decryptData = [self rsaDecryptData: data];
    NSString *result = [[NSString alloc] initWithData:decryptData encoding:NSUTF8StringEncoding];
    return result;
}

/**
 *  解密
 *
 *  @param data 密文data
 *
 *  @return  明文data
 */
- (NSData*)rsaDecryptData:(NSData*)data {
    SecKeyRef key = [self getPrivateKey];
    size_t cipherLen = [data length];
    void *cipher = malloc(cipherLen);
    [data getBytes:cipher length:cipherLen];
    size_t plainLen = SecKeyGetBlockSize(key) - 12;
    void *plain = malloc(plainLen);
    OSStatus status = SecKeyDecrypt(key, kSecPaddingPKCS1, cipher, cipherLen, plain, &plainLen);
    
    if (status != noErr) {
        return nil;
    }
    NSData *decryptedData = [[NSData alloc] initWithBytes:(const void *)plain length:plainLen];
    return decryptedData;
}

@end
