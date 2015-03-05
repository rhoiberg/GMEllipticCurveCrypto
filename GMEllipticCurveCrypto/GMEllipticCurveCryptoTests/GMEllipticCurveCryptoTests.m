//
//  EBNGMEllipticCurveCryptoTest.m
//
//
//

#import <UIKit/UIKit.h>
#import <XCTest/XCTest.h>

#import "GMEllipticCurveCrypto.h"
#import "GMEllipticCurveCrypto+hash.h"

@interface GMEllipticCurveCryptoTest : XCTestCase
@end

@implementation GMEllipticCurveCryptoTest

- (void)setUp
{

    [super setUp];
    // Put setup code here. This method is called before the invocation of each test method in the class.
}

- (void)tearDown
{
    // Put teardown code here. This method is called after the invocation of each test method in the class.
    [super tearDown];
}

- (void)testExample
{
    // This is an example of a functional test case.
    XCTAssert(YES, @"Pass");
}

- (void) testPublicKeyGeneration
{
	GMEllipticCurveCrypto *crypto = [GMEllipticCurveCrypto generateKeyPairForCurve:GMEllipticCurveSecp256r1];
	XCTAssertNotNil(crypto.publicKeyBase64);
}

- (void) testPrivateKeyGeneration
{
	GMEllipticCurveCrypto *crypto = [GMEllipticCurveCrypto generateKeyPairForCurve:GMEllipticCurveSecp256r1];
	XCTAssertNotNil(crypto.privateKeyBase64);
	
}

- (void) testSignAndVerify
{
	GMEllipticCurveCrypto *crypto = [GMEllipticCurveCrypto generateKeyPairForCurve:GMEllipticCurveSecp256r1];
	NSString *nonce = @"This is some random data to be signed by a private key and then verified.";
	NSData* dataToSign = [nonce dataUsingEncoding:NSUTF8StringEncoding];

	NSData *signature = [crypto hashSHA256AndSignData:dataToSign];
	BOOL valid = [crypto hashSHA256AndVerifySignature:signature forData:dataToSign];
	XCTAssertTrue(valid);
}

- (void) testAddKey
{
	[self deleteKey];
	GMEllipticCurveCrypto *crypto = [GMEllipticCurveCrypto generateKeyPairForCurve:GMEllipticCurveSecp256r1];
	CFErrorRef error = NULL;
	
	// Should be the secret invalidated when passcode is removed? If not then use kSecAttrAccessibleWhenUnlocked
	SecAccessControlRef sacObject = SecAccessControlCreateWithFlags(kCFAllocatorDefault,
																	kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly,
																	kSecAccessControlUserPresence, &error);
	if(sacObject == NULL || error != NULL)
	{
		NSLog(@"can't create sacObject: %@", error);
		return;
	}
	
	// we want the operation to fail if there is an item which needs authentication so we will use
	// kSecUseNoAuthenticationUI
	NSDictionary *attributes = @{
								 (__bridge id)kSecClass: (__bridge id)kSecClassKey,
								 (__bridge id)kSecAttrApplicationTag: @"test EC Key",
								 (__bridge id)kSecAttrKeyType:(__bridge id)kSecAttrKeyTypeEC,
								 (__bridge id)kSecValueData: crypto.privateKey,
								 (__bridge id)kSecUseNoAuthenticationUI: @YES,
								 (__bridge id)kSecAttrAccessControl: (__bridge_transfer id)sacObject
								 };
	
	OSStatus status = SecItemAdd((__bridge CFDictionaryRef)attributes, nil);
	XCTAssertTrue(status == errSecSuccess);

	crypto.privateKey = [self ecPrivateKey];
	NSString *nonce = @"This is some random data to be signed by a private key and then verified.";
	NSData* dataToSign = [nonce dataUsingEncoding:NSUTF8StringEncoding];
	NSData *signature = [crypto hashSHA256AndSignData:dataToSign];
	BOOL valid = [crypto hashSHA256AndVerifySignature:signature forData:dataToSign];
	XCTAssertTrue(valid);
}

- (NSData *) ecPrivateKey
{
	NSDictionary *query = @{
							(__bridge id)kSecClass: (__bridge id)kSecClassKey,
							(__bridge id)kSecAttrApplicationTag: @"test EC Key",
							(__bridge id)kSecAttrKeyType:(__bridge id)kSecAttrKeyTypeEC,
							(__bridge id)kSecReturnData: @YES
							};
	
	SecKeyRef dataTypeRef = NULL;
	SecItemCopyMatching((__bridge CFDictionaryRef)(query), (CFTypeRef *)&dataTypeRef);
	return (__bridge NSData *)dataTypeRef;

}

- (void) deleteKey
{
	NSDictionary *query = @{
							(__bridge id)kSecClass: (__bridge id)kSecClassKey,
							(__bridge id)kSecAttrApplicationTag: @"test EC Key",
							(__bridge id)kSecAttrKeyType:(__bridge id)kSecAttrKeyTypeEC
							};
	
	OSStatus status = SecItemDelete((__bridge CFDictionaryRef)(query));
	XCTAssertTrue(status == errSecSuccess);
}
@end
