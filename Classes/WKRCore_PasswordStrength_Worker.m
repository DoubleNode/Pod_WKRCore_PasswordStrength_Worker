//
//  WKRCore_PasswordStrength_Worker.m
//  DoubleNode Core
//
//  Created by Darren Ehlers on 2016/10/16.
//  Copyright © 2016 Darren Ehlers and DoubleNode, LLC. All rights reserved.
//

#import <DNCore/DNCUtilities.h>

#import "WKRCore_PasswordStrength_Worker.h"

#define WKRPWD_MINLEN   6

NSString* const kWkrRegexPasswordOneUppercase   = @"^(?=.*[A-Z]).*$";       // Should contains one or more uppercase letters
NSString* const kWkrRegexPasswordOneLowercase   = @"^(?=.*[a-z]).*$";       // Should contains one or more lowercase letters
NSString* const kWkrRegexPasswordOneNumber      = @"^(?=.*[0-9]).*$";       // Should contains one or more number
NSString* const kWkrRegexPasswordOneSymbol      = @"^(?=.*[!@#$%&_]).*$";   // Should contains one or more symbol

@implementation WKRCore_PasswordStrength_Worker

@synthesize nextBaseWorker;
@synthesize nextPasswordStrengthWorker;

+ (instancetype _Nonnull)worker   {   return [self worker:nil]; }

+ (instancetype _Nonnull)worker:(nullable id<PTCLPasswordStrength_Protocol>)nextPasswordStrengthWorker
{
    return [[self.class alloc] initWithWorker:nextPasswordStrengthWorker];
}

- (nonnull instancetype)init
{
    self = [super init];
    if (self)
    {
        self.nextPasswordStrengthWorker = nil;
    }
    
    return self;
}

- (nonnull instancetype)initWithWorker:(nullable id<PTCLPasswordStrength_Protocol>)nextPasswordStrengthWorker_
{
    self = [super initWithWorker:nextPasswordStrengthWorker_];
    if (self)
    {
        self.nextPasswordStrengthWorker = nextPasswordStrengthWorker_;
    }
    
    return self;
}

#pragma mark - Configuration

- (void)configure
{
    [super configure];
    
    // Worker Dependency Injection
}

#pragma mark - Common Methods

- (void)enableOption:(nonnull NSString*)option
{
}

- (void)disableOption:(nonnull NSString*)option
{
}

#pragma mark - Business Logic

- (WKRPasswordStrengthType)doCheckPasswordStrength:(NSString*)password
{
    NSUInteger  len = password.length;
    
    //will contains password strength
    int strength = 0;
    
    if (len == 0)
    {
        return WKRPasswordStrengthTypeWeak;
    }
    else if (len <= (WKRPWD_MINLEN - 1))
    {
        strength++;
    }
    else if (len <= 10)
    {
        strength += 2;
    }
    else
    {
        strength += 3;
    }
    
    strength += [self utilityValidateString:password   withPattern:kWkrRegexPasswordOneUppercase   caseSensitive:YES];
    strength += [self utilityValidateString:password   withPattern:kWkrRegexPasswordOneLowercase   caseSensitive:YES];
    strength += [self utilityValidateString:password   withPattern:kWkrRegexPasswordOneNumber      caseSensitive:YES];
    strength += [self utilityValidateString:password   withPattern:kWkrRegexPasswordOneSymbol      caseSensitive:YES];
    
    if (strength <= 3)
    {
        return WKRPasswordStrengthTypeWeak;
    }
    else if ((3 < strength) && (strength < 6))
    {
        return WKRPasswordStrengthTypeModerate;
    }
    else
    {
        return WKRPasswordStrengthTypeStrong;
    }
}

- (int)utilityValidateString:(NSString*)string
                 withPattern:(NSString*)pattern
               caseSensitive:(BOOL)caseSensitive
{
    NSError*    error = nil;
    
    NSRegularExpression*    regex = [NSRegularExpression regularExpressionWithPattern:pattern
                                                                              options:((caseSensitive) ? 0 : NSRegularExpressionCaseInsensitive)
                                                                                error:&error];
    NSAssert(regex, @"Unable to create regular expression");
    if (error)
    {
        DNCLog(DNCLL_Debug, DNCLD_General, @"error = %@", error);
    }
    
    NSRange textRange   = NSMakeRange(0, string.length);
    NSRange matchRange  = [regex rangeOfFirstMatchInString:string
                                                   options:NSMatchingReportProgress
                                                     range:textRange];
    
    BOOL didValidate = 0;
    
    // Did we find a matching range
    if (matchRange.location != NSNotFound)
    {
        didValidate = 1;
    }
    
    return didValidate;
}

@end
