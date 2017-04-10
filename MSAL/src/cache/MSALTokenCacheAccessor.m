// Copyright (c) Microsoft Corporation.
// All rights reserved.
//
// This code is licensed under the MIT License.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files(the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and / or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions :
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.

#import "MSALTokenCacheAccessor.h"
#import "MSALAccessTokenCacheItem.h"
#import "MSALRefreshTokenCacheItem.h"
#import "MSALRefreshTokenCacheKey.h"
#import "MSALAccessTokenCacheKey.h"
#import "MSALTokenResponse.h"

@implementation MSALTokenCacheAccessor
{
    id<MSALTokenCacheDataSource> _dataSource;
}

- (id)initWithDataSource:(id<MSALTokenCacheDataSource>)dataSource
{
    if (!(self = [super init]))
    {
        return nil;
    }
    
    _dataSource = dataSource;
    
    return self;
}

- (id<MSALTokenCacheDataSource>)dataSource
{
    return _dataSource;
}

- (MSALAccessTokenCacheItem *)saveAccessAndRefreshToken:(MSALRequestParameters *)requestParam
                                               response:(MSALTokenResponse *)response
                                                  error:(NSError * __autoreleasing *)error
{
    MSALAccessTokenCacheItem *accessToken = [[MSALAccessTokenCacheItem alloc] initWithAuthority:requestParam.unvalidatedAuthority
                                                                                       clientId:requestParam.clientId
                                                                                       response:response];
    //delete all cache entries with intersecting scopes
    //this should not happen but we have this as a safe guard against multiple matches
    NSArray<MSALAccessTokenCacheItem *> *allAccessTokens = [self allAccessTokensForUser:accessToken.user clientId:accessToken.clientId error:nil];
    NSMutableArray<MSALAccessTokenCacheItem *> *overlappingTokens = [NSMutableArray<MSALAccessTokenCacheItem *> new];
    for (MSALAccessTokenCacheItem *tokenItem in allAccessTokens)
    {
        if ([tokenItem.authority isEqualToString:accessToken.authority]
            && [tokenItem.user.userIdentifier isEqualToString:accessToken.user.userIdentifier]
            && [tokenItem.scope intersectsOrderedSet:accessToken.scope])
        {
            [overlappingTokens addObject:tokenItem];
        }
    }
    for (MSALAccessTokenCacheItem *itemToDelete in overlappingTokens)
    {
        [self deleteAccessToken:itemToDelete error:nil];
    }
    
    
    [self saveAccessToken:accessToken error:error];
    
    if (response.refreshToken)
    {
        MSALRefreshTokenCacheItem *refreshToken = [[MSALRefreshTokenCacheItem alloc] initWithEnvironment:requestParam.unvalidatedAuthority.host
                                                                                                clientId:requestParam.clientId
                                                                                                response:response];
        [self saveRefreshToken:refreshToken error:error];
    }
    
    return accessToken;
}

- (BOOL)saveRefreshToken:(MSALRefreshTokenCacheItem *)rtItem
                   error:(NSError * __autoreleasing *)error
{
    return [_dataSource addOrUpdateRefreshTokenItem:rtItem correlationId:nil error:error];
}

- (BOOL)saveAccessToken:(MSALAccessTokenCacheItem *)atItem
                  error:(NSError * __autoreleasing *)error
{
    return [_dataSource addOrUpdateAccessTokenItem:atItem correlationId:nil error:error];
}

- (MSALAccessTokenCacheItem *)findAccessToken:(MSALRequestParameters *)requestParam
                                        error:(NSError * __autoreleasing *)error
{
    MSALAccessTokenCacheKey *key = [[MSALAccessTokenCacheKey alloc] initWithAuthority:requestParam.unvalidatedAuthority.absoluteString
                                                                             clientId:requestParam.clientId
                                                                                scope:requestParam.scopes
                                                                       userIdentifier:requestParam.user.userIdentifier
                                                                          environment:requestParam.user.environment];
    
    NSArray<MSALAccessTokenCacheItem *> *allAccessTokens = [self allAccessTokensForUser:requestParam.user clientId:requestParam.clientId error:error];
    NSMutableArray<MSALAccessTokenCacheItem *> *matchedTokens = [NSMutableArray<MSALAccessTokenCacheItem *> new];
    
    for (MSALAccessTokenCacheItem *tokenItem in allAccessTokens)
    {
        if ([key matches:[tokenItem tokenCacheKey:nil]])
        {
            [matchedTokens addObject:tokenItem];
        }
    }
    
    if (matchedTokens.count != 1)
    {
        return nil;
    }
    
    return matchedTokens[0];
}

- (MSALRefreshTokenCacheItem *)findRefreshToken:(MSALRequestParameters *)requestParam
                                          error:(NSError * __autoreleasing *)error
{
    MSALRefreshTokenCacheKey *key = [[MSALRefreshTokenCacheKey alloc] initWithEnvironment:requestParam.unvalidatedAuthority.host
                                                                                 clientId:requestParam.clientId
                                                                           userIdentifier:requestParam.user.userIdentifier];
    
    NSArray<MSALRefreshTokenCacheItem *> *allRefreshTokens = [self allRefreshTokensForUser:requestParam.user clientId:requestParam.clientId error:error];
    NSMutableArray<MSALRefreshTokenCacheItem *> *matchedTokens = [NSMutableArray<MSALRefreshTokenCacheItem *> new];
    
    for (MSALRefreshTokenCacheItem *tokenItem in allRefreshTokens)
    {
        if ([key matches:[tokenItem tokenCacheKey:nil]])
        {
            [matchedTokens addObject:tokenItem];
        }
    }
    
    if (matchedTokens.count != 1)
    {
        return nil;
    }
    
    return matchedTokens[0];
}

- (BOOL)deleteAccessToken:(MSALAccessTokenCacheItem *)atItem
                    error:(NSError * __autoreleasing *)error
{
    MSALAccessTokenCacheKey *key = [atItem tokenCacheKey:error];
    if (!key)
    {
        return NO;
    }
    
    return [_dataSource removeAccessTokenItem:atItem error:error];
}

- (BOOL)deleteRefreshToken:(MSALRefreshTokenCacheItem *)rtItem
                     error:(NSError * __autoreleasing *)error
{
    MSALRefreshTokenCacheKey *key = [rtItem tokenCacheKey:error];
    if (!key)
    {
        return NO;
    }
    
    return [_dataSource removeRefreshTokenItem:rtItem error:error];
}

- (BOOL)deleteAllTokensForUser:(MSALUser *)user
                      clientId:(NSString *)clientId
                         error:(NSError * __autoreleasing *)error
{
    if (!user)
    {
        return YES;
    }
    
    return [_dataSource removeAllTokensForUserIdentifier:user.userIdentifier
                                             environment:user.environment
                                                clientId:clientId
                                                   error:error];
}


- (NSArray<MSALUser *> *)getUsers:(NSString *)clientId
{
    NSArray<MSALRefreshTokenCacheItem *> *allRefreshTokens = [self allRefreshTokensForUser:nil clientId:clientId error:nil];
    NSMutableDictionary<NSString *, MSALUser *> *allUsers = [NSMutableDictionary<NSString *, MSALUser *> new];
    
    for (MSALRefreshTokenCacheItem *tokenItem in allRefreshTokens)
    {
        [allUsers setValue:tokenItem.user
                    forKey:[MSALTokenCacheKeyBase userIdAtEnvironmentBase64:tokenItem.user.userIdentifier environment:tokenItem.user.environment]];
    }
    return allUsers.allValues;
}

- (NSArray<MSALAccessTokenCacheItem *> *)allAccessTokensForUser:(MSALUser *)user
                                                       clientId:(NSString *)clientId
                                                          error:(NSError * __autoreleasing *)error
{
    MSALAccessTokenCacheKey *key = [[MSALAccessTokenCacheKey alloc] initWithAuthority:nil
                                                                             clientId:nil
                                                                                scope:nil
                                                                       userIdentifier:user.userIdentifier
                                                                          environment:user.environment];
    
    NSArray *accessTokens = [_dataSource getAccessTokenItemsWithKey:key correlationId:nil error:error];
    NSMutableArray *matchedAccessTokens = [NSMutableArray new];
    
    for (MSALAccessTokenCacheItem *token in accessTokens)
    {
        if (!clientId || [clientId isEqualToString:token.clientId])
        {
            [matchedAccessTokens addObject:token];
        }
    }
    
    return matchedAccessTokens;
}

- (NSArray<MSALRefreshTokenCacheItem *> *)allRefreshTokensForUser:(MSALUser *)user
                                                         clientId:(NSString *)clientId
                                                            error:(NSError * __autoreleasing *)error
{
    MSALRefreshTokenCacheKey *key = [[MSALRefreshTokenCacheKey alloc] initWithEnvironment:user.environment
                                                                                 clientId:nil
                                                                           userIdentifier:user.userIdentifier];
    
    NSArray *refreshTokens = [_dataSource getRefreshTokenItemsWithKey:key correlationId:nil error:error];
    NSMutableArray *matchedRefreshTokens = [NSMutableArray new];
    
    for (MSALRefreshTokenCacheItem *token in refreshTokens)
    {
        if (!clientId || [clientId isEqualToString:token.clientId])
        {
            [matchedRefreshTokens addObject:token];
        }
    }
    
    return matchedRefreshTokens;
}

@end