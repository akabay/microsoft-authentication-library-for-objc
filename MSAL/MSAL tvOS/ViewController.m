//
//  ViewController.m
//  MSAL tvOS
//
//  Created by annie on 7/24/18.
//  Copyright © 2018 Microsoft. All rights reserved.
//

#import "ViewController.h"
@interface ViewController ()

@property (nonatomic, strong) NSString *accountIdentifier;
@property (nonatomic, strong) IBOutlet UITextView *textbox;
@property (nonatomic, strong) MSALPublicClientApplication *application;
@property (nonatomic, strong) MSALAccount *account;
@end

@implementation ViewController

- (void)viewDidLoad
{
    [super viewDidLoad];
    self.textbox.selectable = YES;
    [self createPublicClientApplication];
    
}

- (void)createPublicClientApplication
{
    NSError *error = nil;
    
    self.application = [[MSALPublicClientApplication alloc] initWithClientId:@"4b0db8c2-9f26-4417-8bde-3f0e3656f8e0" error:&error];
    
    if (!self.application)
    {
        // Do something in UI - show an error in the textfield
        self.textbox.text = @"Login Unsuccessful";
    }
}

- (IBAction)acquireToken:(id)sender
{
    [self.application acquireTokenForScopes:@[@"user.read", @"tasks.read"]
                            completionBlock:^(MSALResult *result, NSError *error)
     {
         if (!error)
         {
             self.account = result.account;
             self.accountIdentifier = result.account.homeAccountId.identifier;
             // Show result in the textfield
             self.textbox.text = [NSString stringWithFormat:@"Login was successful, Account: %@,  Access Token: %@", result.account, result.accessToken];
         }
         else
         {
             {
                 self.textbox.text = [NSString stringWithFormat:@"Failed to acquire token: %@", error];
             }
         }
     }];
}

- (IBAction)acquireTokenSilent:(id)sender
{
    
    [self.application acquireTokenSilentForScopes:@[@"user.read"]
                                          account:self.account
                            completionBlock:^(MSALResult *result, NSError *error)
     {
         if (!error)
         {
             self.accountIdentifier = result.account.homeAccountId.identifier;
             //NSString *accessToken = result.accessToken
             // Show result in the textfield
             self.textbox.text = [NSString stringWithFormat:@"Login was successful, Account: %@, Access Token: %@", result.account, result.accessToken];
         }
         else
         {
             // Check the error and show result in the textfield
             if ([error.domain isEqual:MSALErrorDomain] && error.code == MSALErrorInteractionRequired)
             {
                 //call interactive method
                 [self.application acquireTokenSilentForScopes:@[@"user.read"]
                                                       account:self.account
                                               completionBlock:^(MSALResult *result, NSError *error) {}];
             }
             else
             {
                 self.textbox.text = [NSString stringWithFormat:@"Failed to acquire token silently: %@", error];
             }
         }
     }];
}
- (IBAction)importCache:(id)sender {
    
}

- (IBAction)deleteAccessToken:(id)sender {
    
}
- (void)didReceiveMemoryWarning {
    [super didReceiveMemoryWarning];
    // Dispose of any resources that can be recreated.
}

@end
