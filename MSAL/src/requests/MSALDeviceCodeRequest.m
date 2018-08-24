//
//  MSALDeviceCodeRequest.m
//  MSAL
//
//  Created by annie on 8/8/18.
//  Copyright © 2018 Microsoft. All rights reserved.
//

#import "MSALDeviceCodeRequest.h"
#import "MSALAuthority.h"
#import "MSALUIBehavior_Internal.h"
#import "MSALTelemetryApiId.h"
#import "MSALPkce.h"
#import "MSALTelemetryAPIEvent.h"
#import "MSIDTelemetry+Internal.h"
#import "MSIDTelemetryEventStrings.h"
#import "MSIDDeviceId.h"
#import "MSALAccount+Internal.h"
#import "MSALAccountId.h"


static MSALDeviceCodeRequest *s_currentRequest = nil;


@implementation MSALDeviceCodeRequest

{
    NSString *_code;
    MSALPkce *_pkce;
}

- (id)initWithParameters:(MSALRequestParameters *)parameters
    extraScopesToConsent:(NSArray<NSString *> *)extraScopesToConsent
                behavior:(MSALUIBehavior)behavior
              tokenCache:(MSIDDefaultTokenCacheAccessor *)tokenCache
                   error:(NSError * __autoreleasing *)error
{
    if (!(self = [super initWithParameters:parameters
                                tokenCache:tokenCache
                                     error:error]))
    {
        return nil;
    }

    if (extraScopesToConsent)
    {
        _extraScopesToConsent = [[NSOrderedSet alloc] initWithArray:extraScopesToConsent];
        if (![self validateScopeInput:_extraScopesToConsent error:error])
        {
            return nil;
        }
    }

    _uiBehavior = behavior;
    _pkce = [MSALPkce new];
    
    return self;
}

+ (MSALDeviceCodeRequest *)currentActiveRequest
{
    return s_currentRequest;
}

- (NSMutableDictionary<NSString *, NSString *> *)authorizationParameters
{
    NSMutableDictionary<NSString *, NSString *> *parameters = [NSMutableDictionary new];
    if (_parameters.extraQueryParameters)
    {
        [parameters addEntriesFromDictionary:_parameters.extraQueryParameters];
    }
    MSALScopes *allScopes = [self requestScopes:_extraScopesToConsent];
    parameters[MSID_OAUTH2_CLIENT_ID] = _parameters.clientId;
    parameters[MSID_OAUTH2_SCOPE] = [allScopes msalToString];
    parameters[MSID_OAUTH2_RESPONSE_TYPE] = MSID_OAUTH2_CODE;
    parameters[MSID_OAUTH2_REDIRECT_URI] = [_parameters.redirectUri absoluteString];
    parameters[MSID_OAUTH2_CORRELATION_ID_REQUEST] = [_parameters.correlationId UUIDString];
    parameters[MSID_OAUTH2_LOGIN_HINT] = _parameters.loginHint;
    
    // PKCE:
    parameters[MSID_OAUTH2_CODE_CHALLENGE] = _pkce.codeChallenge;
    parameters[MSID_OAUTH2_CODE_CHALLENGE_METHOD] = _pkce.codeChallengeMethod;
    
    NSDictionary *msalId = [MSIDDeviceId deviceId];
    [parameters addEntriesFromDictionary:msalId];
    [parameters addEntriesFromDictionary:MSALParametersForBehavior(_uiBehavior)];
    
    return parameters;
}

- (NSURL *)authorizationUrl
{
    NSURLComponents *urlComponents =
    [[NSURLComponents alloc] initWithURL:_authority.authorizationEndpoint
                 resolvingAgainstBaseURL:NO];
    
    // Query parameters can come through from the OIDC discovery on the authorization endpoint as well
    // and we need to retain them when constructing our authorization uri
    NSMutableDictionary <NSString *, NSString *> *parameters = [self authorizationParameters];
    if (urlComponents.percentEncodedQuery)
    {
        NSDictionary *authorizationQueryParams = [NSDictionary msidURLFormDecode:urlComponents.percentEncodedQuery];
        if (authorizationQueryParams)
        {
            [parameters addEntriesFromDictionary:authorizationQueryParams];
        }
    }
    
    if (_parameters.sliceParameters)
    {
        [parameters addEntriesFromDictionary:_parameters.sliceParameters];
    }
    
    MSALAccount *account = _parameters.account;
    if (account)
    {
        parameters[MSID_OAUTH2_LOGIN_HINT] = account.username;
        parameters[MSID_OAUTH2_LOGIN_REQ] = account.homeAccountId.objectId;
        parameters[MSID_OAUTH2_DOMAIN_REQ] = account.homeAccountId.tenantId;
    }
    
    _state = [[NSUUID UUID] UUIDString];
    parameters[MSID_OAUTH2_STATE] = _state;
    
    urlComponents.percentEncodedQuery = [parameters msidURLFormEncode];
    
    return [urlComponents URL];
}

- (void)run:(MSALCompletionBlock)completionBlock
{
    [super run:^(MSALResult *result, NSError *error)
     {
         // Make sure that any response to an interactive request is returned on
         // the main thread.
         dispatch_async(dispatch_get_main_queue(), ^{
             completionBlock(result, error);
         });
     }];
}

- (void)acquireToken:(MSALCompletionBlock)completionBlock
{
    [super resolveEndpoints:^(MSALAuthority *authority, NSError *error) {
        if (error)
        {
            MSALTelemetryAPIEvent *event = [self getTelemetryAPIEvent];
            [self stopTelemetryEvent:event error:error];
            
            completionBlock(nil, error);
            return;
        }
        
        self->_authority = authority;
        [self acquireTokenImpl:completionBlock];
    }];
}

- (void)acquireTokenImpl:(MSALCompletionBlock)completionBlock
{
    NSURL *authorizationUrl = [self authorizationUrl];
    
    MSID_LOG_INFO(_parameters, @"Launching Web UI");
    MSID_LOG_INFO_PII(_parameters, @"Launching Web UI with URL: %@", authorizationUrl);
    s_currentRequest = self;

    NSString *urlstring = [NSString stringWithFormat:@"%@/oauth2/devicecode", _parameters.unvalidatedAuthority.absoluteString];
    
    NSMutableURLRequest *request = [[NSMutableURLRequest alloc]
                        initWithURL:[NSURL
                                     URLWithString:urlstring]];
    [request setHTTPMethod:@"POST"];
    [request setValue:@"application/x-www-form-urlencoded"
            forHTTPHeaderField:@"Content-type"];

    NSString *body = [NSString stringWithFormat:@"grant_type=device_code&clientId=%@&resource=https://graph.windows.net", _parameters.clientId];
    
    [request setHTTPBody:[body
                          dataUsingEncoding:NSUTF8StringEncoding]];
    
    [[[NSURLSession sharedSession] dataTaskWithRequest:request completionHandler:^(NSData * _Nullable data, NSURLResponse * _Nullable response, NSError * _Nullable error)
    {
        NSJSONSerialization
    }] resume];
    
    NSString *path = [[NSBundle mainBundle] pathForResource:@"json" ofType:@"txt"];
    NSString *jsonString = [[NSString alloc] initWithData:(nonnull NSData *) encoding:<#(NSStringEncoding)#>:path encoding:NSUTF8StringEncoding error:nil];
    //NSString *jsonString = [[NSString alloc] initWithContentsOfFile:path encoding:NSUTF8StringEncoding error:nil];
    NSData *jsonData = [NSData dataWithContentsOfFile:path];
        
    NSError *error = nil;

    id object = [NSJSONSerialization JSONObjectWithData:jsonData options:NSJSONReadingAllowFragments error:&error];
    
    if ([object isKindOfClass:[NSDictionary class]] && error == nil)
    {
        NSLog(@"dictionary: %@", object);
        
        NSString *usercode;
        usercode = [object objectForKey:@"user_code"];
        NSLog(@"user_code: %@", usercode);
        
        NSString *verURL;
        verURL = [object objectForKey:@"verification_url"];
        NSLog(@"verification_url: %@", verURL);
    }
    
    else
    {
        // Show error in the textfield
    }
}

- (void)addAdditionalRequestParameters:(NSMutableDictionary<NSString *, NSString *> *)parameters
{
    parameters[MSID_OAUTH2_GRANT_TYPE] = MSID_OAUTH2_AUTHORIZATION_CODE;
    parameters[MSID_OAUTH2_CODE] = _code;
    parameters[MSID_OAUTH2_REDIRECT_URI] = [_parameters.redirectUri absoluteString];
    
    // PKCE
    parameters[MSID_OAUTH2_CODE_VERIFIER] = _pkce.codeVerifier;
}

- (MSALTelemetryAPIEvent *)getTelemetryAPIEvent
{
    MSALTelemetryAPIEvent *event = [super getTelemetryAPIEvent];
    [event setUIBehavior:_uiBehavior];
    return event;
}

@end
