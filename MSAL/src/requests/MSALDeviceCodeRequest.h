//
//  MSALDeviceCodeRequest.h
//  MSAL
//
//  Created by annie on 8/8/18.
//  Copyright © 2018 Microsoft. All rights reserved.
//

#import "MSALBaseRequest.h"

@interface MSALDeviceCodeRequest : MSALBaseRequest
{
    MSALScopes *_extraScopesToConsent;
    MSALUIBehavior _uiBehavior;
}

@property NSString *state;

@end
