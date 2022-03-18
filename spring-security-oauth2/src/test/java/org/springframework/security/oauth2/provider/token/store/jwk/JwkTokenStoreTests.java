/*
 * Copyright 2012-2017 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.springframework.security.oauth2.provider.token.store.jwk;

import org.junit.Rule;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.runner.RunWith;
import org.mockito.ArgumentMatchers;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.stubbing.Answer;
import org.springframework.security.jwt.crypto.sign.SignatureVerifier;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.OAuth2Request;
import org.springframework.security.oauth2.provider.token.AccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.JwtClaimsSetVerifier;
import org.springframework.security.oauth2.provider.token.store.JwtTokenStore;
import org.springframework.util.ReflectionUtils;
import java.lang.reflect.Field;
import java.util.LinkedHashMap;
import java.util.Map;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Matchers.any;
import static org.mockito.Matchers.anyString;
import static org.mockito.Mockito.*;

/**
 * @author Joe Grandja
 */
@ExtendWith(MockitoExtension.class)
class JwkTokenStoreTests {

    private JwkTokenStore jwkTokenStore = new JwkTokenStore("https://identity.server1.io/token_keys");

    @Test
    void readAuthenticationUsingOAuth2AccessTokenWhenCalledThenDelegateCalled() throws Exception {
        JwkTokenStore spy = spy(this.jwkTokenStore);
        JwtTokenStore delegate = mock(JwtTokenStore.class);
        when(delegate.readAuthentication(any(OAuth2AccessToken.class))).thenReturn(null);
        Field field = ReflectionUtils.findField(spy.getClass(), "delegate");
        field.setAccessible(true);
        ReflectionUtils.setField(field, spy, delegate);
        spy.readAuthentication(mock(OAuth2AccessToken.class));
        verify(delegate).readAuthentication(any(OAuth2AccessToken.class));
    }

    @Test
    void readAuthenticationUsingAccessTokenStringWhenCalledThenDelegateCalled() throws Exception {
        JwkTokenStore spy = spy(this.jwkTokenStore);
        JwtTokenStore delegate = mock(JwtTokenStore.class);
        when(delegate.readAuthentication(anyString())).thenReturn(null);
        Field field = ReflectionUtils.findField(spy.getClass(), "delegate");
        field.setAccessible(true);
        ReflectionUtils.setField(field, spy, delegate);
        spy.readAuthentication(anyString());
        verify(delegate).readAuthentication(anyString());
    }

    // gh-1015
    @Test
    void readAuthenticationUsingCustomAccessTokenConverterThenAuthenticationDetailsContainsClaims() throws Exception {
        AccessTokenConverter customAccessTokenConverter = mock(AccessTokenConverter.class);
        when(customAccessTokenConverter.extractAuthentication(anyMapOf(String.class, String.class))).thenAnswer(new Answer<OAuth2Authentication>() {

            @Override
            public OAuth2Authentication answer(InvocationOnMock invocation) throws Throwable {
                Map<String, String> claims = (Map<String, String>) invocation.getArguments()[0];
                OAuth2Authentication authentication = new OAuth2Authentication(mock(OAuth2Request.class), null);
                authentication.setDetails(claims);
                return authentication;
            }
        });
        JwkVerifyingJwtAccessTokenConverter jwtVerifyingAccessTokenConverter = new JwkVerifyingJwtAccessTokenConverter(mock(JwkDefinitionSource.class));
        jwtVerifyingAccessTokenConverter = spy(jwtVerifyingAccessTokenConverter);
        jwtVerifyingAccessTokenConverter.setAccessTokenConverter(customAccessTokenConverter);
        Map<String, String> claims = new LinkedHashMap<String, String>();
        claims.put("claim1", "value1");
        claims.put("claim2", "value2");
        claims.put("claim3", "value3");
        doReturn(claims).when(jwtVerifyingAccessTokenConverter).decode((anyString()));
        JwkTokenStore spy = spy(this.jwkTokenStore);
        JwtTokenStore delegate = new JwtTokenStore(jwtVerifyingAccessTokenConverter);
        Field field = ReflectionUtils.findField(spy.getClass(), "delegate");
        field.setAccessible(true);
        ReflectionUtils.setField(field, spy, delegate);
        OAuth2Authentication authentication = spy.readAuthentication(anyString());
        assertEquals(claims, authentication.getDetails());
    }

    // gh-1111
    @Test
    void readAccessTokenWhenJwtClaimsSetVerifierIsSetThenVerifyIsCalled() throws Exception {
        JwkDefinition jwkDefinition = mock(JwkDefinition.class);
        when(jwkDefinition.getAlgorithm()).thenReturn(JwkDefinition.CryptoAlgorithm.RS256);
        JwkDefinitionSource.JwkDefinitionHolder jwkDefinitionHolder = mock(JwkDefinitionSource.JwkDefinitionHolder.class);
        when(jwkDefinitionHolder.getJwkDefinition()).thenReturn(jwkDefinition);
        when(jwkDefinitionHolder.getSignatureVerifier()).thenReturn(mock(SignatureVerifier.class));
        JwkDefinitionSource jwkDefinitionSource = mock(JwkDefinitionSource.class);
        when(jwkDefinitionSource.getDefinitionLoadIfNecessary(anyString(), isNull())).thenReturn(jwkDefinitionHolder);
        JwkVerifyingJwtAccessTokenConverter jwtVerifyingAccessTokenConverter = new JwkVerifyingJwtAccessTokenConverter(jwkDefinitionSource);
        JwtClaimsSetVerifier jwtClaimsSetVerifier = mock(JwtClaimsSetVerifier.class);
        jwtVerifyingAccessTokenConverter.setJwtClaimsSetVerifier(jwtClaimsSetVerifier);
        JwkTokenStore spy = spy(this.jwkTokenStore);
        JwtTokenStore delegate = new JwtTokenStore(jwtVerifyingAccessTokenConverter);
        Field field = ReflectionUtils.findField(spy.getClass(), "delegate");
        field.setAccessible(true);
        ReflectionUtils.setField(field, spy, delegate);
        OAuth2AccessToken accessToken = spy.readAccessToken("eyJhbGciOiJSUzI1NiIsImtpZCI6IjEifQ==.eyJ1c2VyX25hbWUiOiJ0ZXN0MiIsImp0aSI6IkZPTyIsImNsaWVudF9pZCI6ImZvbyJ9.b43ob1ALSIwr_J2oEnfMhsXvYkr1qVBNhigNH2zlaE1OQLhLfT-DMlFtHcyUlyap0C2n0q61SPaGE_z715TV0uTAv2YKDN4fKZz2bMR7eHLsvaaCuvs7KCOi_aSROaUG");
        verify(jwtClaimsSetVerifier).verify(ArgumentMatchers.<Map<String, Object>>any());
    }

    @Test
    void readAccessTokenWhenCalledThenDelegateCalled() throws Exception {
        JwkTokenStore spy = spy(this.jwkTokenStore);
        JwtTokenStore delegate = mock(JwtTokenStore.class);
        when(delegate.readAccessToken(anyString())).thenReturn(null);
        Field field = ReflectionUtils.findField(spy.getClass(), "delegate");
        field.setAccessible(true);
        ReflectionUtils.setField(field, spy, delegate);
        spy.readAccessToken(anyString());
        verify(delegate).readAccessToken(anyString());
    }

    @Test
    void removeAccessTokenWhenCalledThenDelegateCalled() throws Exception {
        JwkTokenStore spy = spy(this.jwkTokenStore);
        JwtTokenStore delegate = mock(JwtTokenStore.class);
        Field field = ReflectionUtils.findField(spy.getClass(), "delegate");
        field.setAccessible(true);
        ReflectionUtils.setField(field, spy, delegate);
        spy.removeAccessToken(any(OAuth2AccessToken.class));
        verify(delegate).removeAccessToken(any());
    }

    @Test
    void storeAccessTokenWhenCalledThenThrowJwkException() throws Exception {
        JwkException e = Assertions.assertThrows(JwkException.class, ()-> {
            this.jwkTokenStore.storeAccessToken(null, null);
        });
        assertTrue(e.getMessage().contains("This operation is not supported."));
    }

    @Test
    void storeRefreshTokenWhenCalledThenThrowJwkException() throws Exception {
        JwkException e = Assertions.assertThrows(JwkException.class, ()-> {
            this.jwkTokenStore.storeRefreshToken(null, null);
        });
        assertTrue(e.getMessage().contains("This operation is not supported."));
    }

    @Test
    void readRefreshTokenWhenCalledThenThrowJwkException() throws Exception {
        JwkException e = Assertions.assertThrows(JwkException.class, ()-> {
            this.jwkTokenStore.readRefreshToken(null);
        });
        assertTrue(e.getMessage().contains("This operation is not supported."));
    }

    @Test
    void readAuthenticationForRefreshTokenWhenCalledThenThrowJwkException() throws Exception {
        JwkException e = Assertions.assertThrows(JwkException.class, ()-> {
            this.jwkTokenStore.readAuthenticationForRefreshToken(null);
        });
        assertTrue(e.getMessage().contains("This operation is not supported."));
    }

    @Test
    void removeRefreshTokenWhenCalledThenThrowJwkException() throws Exception {
        JwkException e = Assertions.assertThrows(JwkException.class, ()-> {
            this.jwkTokenStore.removeRefreshToken(null);
        });
        assertTrue(e.getMessage().contains("This operation is not supported."));
    }

    @Test
    void removeAccessTokenUsingRefreshTokenWhenCalledThenThrowJwkException() throws Exception {
        JwkException e = Assertions.assertThrows(JwkException.class, ()-> {
            this.jwkTokenStore.removeAccessTokenUsingRefreshToken(null);
        });
        assertTrue(e.getMessage().contains("This operation is not supported."));
    }

    @Test
    void getAccessTokenWhenCalledThenThrowJwkException() throws Exception {
        JwkException e = Assertions.assertThrows(JwkException.class, ()-> {
            this.jwkTokenStore.getAccessToken(null);
        });
        assertTrue(e.getMessage().contains("This operation is not supported."));
    }

    @Test
    void findTokensByClientIdAndUserNameWhenCalledThenThrowJwkException() throws Exception {
        JwkException e = Assertions.assertThrows(JwkException.class, ()-> {
            this.jwkTokenStore.findTokensByClientIdAndUserName(null, null);
        });
        assertTrue(e.getMessage().contains("This operation is not supported."));
    }

    @Test
    void findTokensByClientIdWhenCalledThenThrowJwkException() throws Exception {
        JwkException e = Assertions.assertThrows(JwkException.class, ()-> {
            this.jwkTokenStore.findTokensByClientId(null);
        });
        assertTrue(e.getMessage().contains("This operation is not supported."));
    }

}
