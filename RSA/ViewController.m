//
//  ViewController.m
//  RSA
//
//  Created by 王盛魁 on 2017/6/23.
//  Copyright © 2017年 WangShengKui. All rights reserved.
//

#import "ViewController.h"
#import "EncryptTool.h"
#import "RSA.h"

#define kPublicKey @"-----BEGIN PUBLIC KEY-----\nMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDg0OkyHID9PSQ+AgONPvjBaKqZ\nm5h1zG57e8uV7kgK+zWs0Hjp1jgRkfAiNvCvAuTcmbcCXLSndJvUPlwwb/5VnH7q\nzeoiAjXj3PnMZbjqUrRnsbJLX1tsqV54GAeB7BjFcgGoXlY7cUyo9H0VH/kBXWAl\n9U3Se4yAf7oJaD/PfwIDAQAB\n-----END PUBLIC KEY-----"
#define kPrivateKey @"-----BEGIN PRIVATE KEY-----MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBAODQ6TIcgP09JD4CA40++MFoqpmbmHXMbnt7y5XuSAr7NazQeOnWOBGR8CI28K8C5NyZtwJctKd0m9Q+XDBv/lWcfurN6iICNePc+cxluOpStGexsktfW2ypXngYB4HsGMVyAaheVjtxTKj0fRUf+QFdYCX1TdJ7jIB/ugloP89/AgMBAAECgYALvt5wH80dbfRWyQQmfQPCFxXSsK5meSfMi8s3KhvZdwZ24O1wSiDjyhwhrX0lp6ENZXqKRQ2rMgxyKk/mt/MxrMhS9Ga7z6NiTv3G4zfN8mPqCHW2/v5XQxy453qPrKtXk2o2YSqeaaHNE+45d5o5v+vIUOExtfHOla1ZF4kpAQJBAPWUzuhqCKAmh4RiL/8c5qW5qAQgwLgDKrOqZkyAqt7w3Ms01CYXYKJkmFMJJzrj23ntr8vCeaslBfz/9oBI7esCQQDqWpPEehoaWC/oIyJOyDBfFVV7WClnizqsbvvyvoeOuYkLJwM4K7759LjgAnqeOiGKgpfoPDMyPBMSlRTu+Tu9AkBJ+FSKNMX8Vx6ihWCnmvDuIgm1lJf31RxbmYvOp0LQfARFQNhV0NzOjTZEbJFgb5mAFFPLL/ytzC0Nk5uP8GeZAkEAnGCyZ5GeZ2PfG8SN+QnmFRx0POj4P+qMzVEFd9YhOGCfjLyMjmfKeJoO3xNoZLqfdQBtgv7gnq2tgGHQZSIT9QJALuQKOFn9cGV8RQtovz9RCUxLHq1W+F83WiKIICmvG2Rx2D76+OTmly2pqC4e7U6WgnNf2ZtPNYuspzc108pd2g==-----END PRIVATE KEY-----"
#define publicFilePath [[NSBundle mainBundle]pathForResource:@"rsacert" ofType:@"der"]
#define privateFilePath [[NSBundle mainBundle]pathForResource:@"p" ofType:@"p12"]
@interface ViewController ()

@end

@implementation ViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    NSString *encyptString = @"解密";
    // 加载公钥、加密
    EncryptTool *tool = [[EncryptTool alloc]init];
    [tool loadPublicKeyFromFile:publicFilePath];
    NSString *returnEncypt = [tool rsaEncryptString:encyptString];
    NSLog(@"加密结果：%@",returnEncypt);
    //    // 加载私钥、解密
    //    [tool loadPrivateKeyFromFile:privateFilePath password:@"123456"];
    //    NSString *returnDecrypt = [tool rsaDecryptString:returnEncypt];;
    //    NSLog(@"解密结果：%@",returnDecrypt);
    
    /* 加密 */
    NSString *encyStr = nil;
    // 利用der文件加密
    //    encyStr = [RSA encryptString:@"解密" publicKeyWithContentsOfFile:publicFilePath];
    // 利用公钥字符串加密
    encyStr = [RSA encryptString:@"解密" publicKey:kPublicKey];
    NSLog(@"en=%@",encyStr);
    
    /*  解密   */
    NSString *deStr = nil;
    // 利用p12文件解密
    //    deStr = [RSA decryptString:returnEncypt privateKeyWithContentsOfFile:privateFilePath password:@"123456"];
    // 利用私钥字符串解密
    deStr = [RSA decryptString:encyStr privateKey:kPrivateKey];
    NSLog(@"de=%@",deStr);
    
    
    
    // Do any additional setup after loading the view, typically from a nib.
}



- (void)didReceiveMemoryWarning {
    [super didReceiveMemoryWarning];
    // Dispose of any resources that can be recreated.
}


@end
