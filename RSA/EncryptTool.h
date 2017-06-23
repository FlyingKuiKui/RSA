//
//  ViewController.m
//  RSA
//
//  Created by 王盛魁 on 2017/6/23.
//  Copyright © 2017年 WangShengKui. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface EncryptTool : NSObject

// 通过der文件路径获取公钥
- (void)loadPublicKeyFromFile:(NSString *)derFilePath;
// 通过p12文件路径获取私钥
- (void)loadPrivateKeyFromFile:(NSString*)p12FilePath password:(NSString*)p12Password;
// 字符串加密
- (NSString *)rsaEncryptString:(NSString *)string;
// 字符串解密
- (NSString *)rsaDecryptString:(NSString*)string;

@end
