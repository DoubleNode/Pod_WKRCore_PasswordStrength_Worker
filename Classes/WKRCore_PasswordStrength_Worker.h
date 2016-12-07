//
//  WKRCore_PasswordStrength_Worker.h
//  DoubleNode Core
//
//  Created by Darren Ehlers on 2016/10/16.
//  Copyright © 2016 Darren Ehlers and DoubleNode, LLC. All rights reserved.
//

#import <DNCProtocols/PTCLPasswordStrength_Protocol.h>
#import <DNCProtocols/__WKR_Base_Worker.h>

@interface WKRCore_PasswordStrength_Worker : WKR_Base_Worker<PTCLPasswordStrength_Protocol>

#pragma mark - Business Logic

- (WKRPasswordStrengthType)doCheckPasswordStrength:(nonnull NSString*)password;

@end
