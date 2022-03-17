package org.springframework.security.oauth2.client;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;
import java.io.IOException;
import java.lang.reflect.Field;
import java.net.URI;
import java.util.Collections;
import java.util.Date;
import java.util.concurrent.atomic.AtomicBoolean;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.client.ClientHttpRequest;
import org.springframework.http.client.ClientHttpRequestFactory;
import org.springframework.http.client.ClientHttpResponse;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.oauth2.client.http.AccessTokenRequiredException;
import org.springframework.security.oauth2.client.resource.BaseOAuth2ProtectedResourceDetails;
import org.springframework.security.oauth2.client.resource.OAuth2ProtectedResourceDetails;
import org.springframework.security.oauth2.client.resource.UserRedirectRequiredException;
import org.springframework.security.oauth2.client.token.AccessTokenProvider;
import org.springframework.security.oauth2.client.token.AccessTokenProviderChain;
import org.springframework.security.oauth2.client.token.AccessTokenRequest;
import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2RefreshToken;
import org.springframework.util.ReflectionUtils;
import org.springframework.web.client.RequestCallback;
import org.springframework.web.client.ResponseExtractor;
import org.springframework.web.util.UriTemplate;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * @author Ryan Heaton
 * @author Dave Syer
 */
class OAuth2RestTemplateTests {

    private BaseOAuth2ProtectedResourceDetails resource;

    private OAuth2RestTemplate restTemplate;

    private AccessTokenProvider accessTokenProvider = Mockito.mock(AccessTokenProvider.class);

    private ClientHttpRequest request;

    private HttpHeaders headers;

    @BeforeEach
    void open() throws Exception {
        resource = new BaseOAuth2ProtectedResourceDetails();
        // Facebook and older specs:
        resource.setTokenName("bearer_token");
        restTemplate = new OAuth2RestTemplate(resource);
        restTemplate.setAccessTokenProvider(accessTokenProvider);
        request = Mockito.mock(ClientHttpRequest.class);
        headers = new HttpHeaders();
        Mockito.when(request.getHeaders()).thenReturn(headers);
        ClientHttpResponse response = Mockito.mock(ClientHttpResponse.class);
        HttpStatus statusCode = HttpStatus.OK;
        Mockito.when(response.getStatusCode()).thenReturn(statusCode);
        Mockito.when(request.execute()).thenReturn(response);
    }

    @Test
    void testNonBearerToken() throws Exception {
        DefaultOAuth2AccessToken token = new DefaultOAuth2AccessToken("12345");
        token.setTokenType("MINE");
        restTemplate.getOAuth2ClientContext().setAccessToken(token);
        ClientHttpRequest http = restTemplate.createRequest(URI.create("https://nowhere.com/api/crap"), HttpMethod.GET);
        String auth = http.getHeaders().getFirst("Authorization");
        assertTrue(auth.startsWith("MINE "));
    }

    @Test
    void testCustomAuthenticator() throws Exception {
        DefaultOAuth2AccessToken token = new DefaultOAuth2AccessToken("12345");
        token.setTokenType("MINE");
        restTemplate.setAuthenticator(new OAuth2RequestAuthenticator() {

            @Override
            public void authenticate(OAuth2ProtectedResourceDetails resource, OAuth2ClientContext clientContext, ClientHttpRequest req) {
                req.getHeaders().set("X-Authorization", clientContext.getAccessToken().getTokenType() + " " + "Nah-nah-na-nah-nah");
            }
        });
        restTemplate.getOAuth2ClientContext().setAccessToken(token);
        ClientHttpRequest http = restTemplate.createRequest(URI.create("https://nowhere.com/api/crap"), HttpMethod.GET);
        String auth = http.getHeaders().getFirst("X-Authorization");
        assertEquals("MINE Nah-nah-na-nah-nah", auth);
    }

    /**
     * tests appendQueryParameter
     */
    @Test
    void testAppendQueryParameter() throws Exception {
        OAuth2AccessToken token = new DefaultOAuth2AccessToken("12345");
        URI appended = restTemplate.appendQueryParameter(URI.create("https://graph.facebook.com/search?type=checkin"), token);
        assertEquals("https://graph.facebook.com/search?type=checkin&bearer_token=12345", appended.toString());
    }

    /**
     * tests appendQueryParameter
     */
    @Test
    void testAppendQueryParameterWithNoExistingParameters() throws Exception {
        OAuth2AccessToken token = new DefaultOAuth2AccessToken("12345");
        URI appended = restTemplate.appendQueryParameter(URI.create("https://graph.facebook.com/search"), token);
        assertEquals("https://graph.facebook.com/search?bearer_token=12345", appended.toString());
    }

    /**
     * tests encoding of access token value
     */
    @Test
    void testDoubleEncodingOfParameterValue() throws Exception {
        OAuth2AccessToken token = new DefaultOAuth2AccessToken("1/qIxxx");
        URI appended = restTemplate.appendQueryParameter(URI.create("https://graph.facebook.com/search"), token);
        assertEquals("https://graph.facebook.com/search?bearer_token=1%2FqIxxx", appended.toString());
    }

    /**
     * tests no double encoding of existing query parameter
     */
    @Test
    void testNonEncodingOfUriTemplate() throws Exception {
        OAuth2AccessToken token = new DefaultOAuth2AccessToken("12345");
        UriTemplate uriTemplate = new UriTemplate("https://graph.facebook.com/fql?q={q}");
        URI expanded = uriTemplate.expand("[q: fql]");
        URI appended = restTemplate.appendQueryParameter(expanded, token);
        assertEquals("https://graph.facebook.com/fql?q=%5Bq:%20fql%5D&bearer_token=12345", appended.toString());
    }

    /**
     * tests URI with fragment value
     */
    @Test
    void testFragmentUri() throws Exception {
        OAuth2AccessToken token = new DefaultOAuth2AccessToken("1234");
        URI appended = restTemplate.appendQueryParameter(URI.create("https://graph.facebook.com/search#foo"), token);
        assertEquals("https://graph.facebook.com/search?bearer_token=1234#foo", appended.toString());
    }

    /**
     * tests encoding of access token value passed in protected requests ref: SECOAUTH-90
     */
    @Test
    void testDoubleEncodingOfAccessTokenValue() throws Exception {
        // try with fictitious token value with many characters to encode
        OAuth2AccessToken token = new DefaultOAuth2AccessToken("1 qI+x:y=z");
        // System.err.println(UriUtils.encodeQueryParam(token.getValue(), "UTF-8"));
        URI appended = restTemplate.appendQueryParameter(URI.create("https://graph.facebook.com/search"), token);
        assertEquals("https://graph.facebook.com/search?bearer_token=1+qI%2Bx%3Ay%3Dz", appended.toString());
    }

    @Test
    void testNoRetryAccessDeniedExceptionForNoExistingToken() throws Exception {
        assertThrows(AccessTokenRequiredException.class, () -> {
            restTemplate.setAccessTokenProvider(new StubAccessTokenProvider());
            restTemplate.setRequestFactory(new ClientHttpRequestFactory() {

                public ClientHttpRequest createRequest(URI uri, HttpMethod httpMethod) throws IOException {
                    throw new AccessTokenRequiredException(resource);
                }
            });
            restTemplate.doExecute(new URI("https://foo"), HttpMethod.GET, new NullRequestCallback(), new SimpleResponseExtractor());
        });
    }

    @Test
    void testRetryAccessDeniedException() throws Exception {
        final AtomicBoolean failed = new AtomicBoolean(false);
        restTemplate.getOAuth2ClientContext().setAccessToken(new DefaultOAuth2AccessToken("TEST"));
        restTemplate.setAccessTokenProvider(new StubAccessTokenProvider());
        restTemplate.setRequestFactory(new ClientHttpRequestFactory() {

            public ClientHttpRequest createRequest(URI uri, HttpMethod httpMethod) throws IOException {
                if (!failed.get()) {
                    failed.set(true);
                    throw new AccessTokenRequiredException(resource);
                }
                return request;
            }
        });
        Boolean result = restTemplate.doExecute(new URI("https://foo"), HttpMethod.GET, new NullRequestCallback(), new SimpleResponseExtractor());
        assertTrue(result);
    }

    @Test
    void testNewTokenAcquiredIfExpired() throws Exception {
        DefaultOAuth2AccessToken token = new DefaultOAuth2AccessToken("TEST");
        token.setExpiration(new Date(System.currentTimeMillis() - 1000));
        restTemplate.getOAuth2ClientContext().setAccessToken(token);
        restTemplate.setAccessTokenProvider(new StubAccessTokenProvider());
        OAuth2AccessToken newToken = restTemplate.getAccessToken();
        assertNotNull(newToken);
        assertTrue(!token.equals(newToken));
    }

    // gh-1478
    @Test
    void testNewTokenAcquiredWithDefaultClockSkew() {
        DefaultOAuth2AccessToken token = new DefaultOAuth2AccessToken("TEST");
        // Default clock skew is 30 secs
        token.setExpiration(new Date(System.currentTimeMillis() + 29000));
        restTemplate.getOAuth2ClientContext().setAccessToken(token);
        restTemplate.setAccessTokenProvider(new StubAccessTokenProvider());
        OAuth2AccessToken newToken = restTemplate.getAccessToken();
        assertNotNull(newToken);
        assertTrue(!token.equals(newToken));
    }

    // gh-1478
    @Test
    void testNewTokenAcquiredIfLessThanConfiguredClockSkew() {
        DefaultOAuth2AccessToken token = new DefaultOAuth2AccessToken("TEST");
        token.setExpiration(new Date(System.currentTimeMillis() + 5000));
        restTemplate.setClockSkew(6);
        restTemplate.getOAuth2ClientContext().setAccessToken(token);
        restTemplate.setAccessTokenProvider(new StubAccessTokenProvider());
        OAuth2AccessToken newToken = restTemplate.getAccessToken();
        assertNotNull(newToken);
        assertTrue(!token.equals(newToken));
    }

    // gh-1478
    @Test
    void testNewTokenNotAcquiredIfGreaterThanConfiguredClockSkew() {
        DefaultOAuth2AccessToken token = new DefaultOAuth2AccessToken("TEST");
        token.setExpiration(new Date(System.currentTimeMillis() + 5000));
        restTemplate.setClockSkew(4);
        restTemplate.getOAuth2ClientContext().setAccessToken(token);
        restTemplate.setAccessTokenProvider(new StubAccessTokenProvider());
        OAuth2AccessToken newToken = restTemplate.getAccessToken();
        assertNotNull(newToken);
        assertTrue(token.equals(newToken));
    }

    // gh-1478
    @Test
    void testNegativeClockSkew() {
        assertThrows(IllegalArgumentException.class, () -> {
            restTemplate.setClockSkew(-1);
        });
    }

    // gh-1909
    @Test
    void testClockSkewPropagationIntoAccessTokenProviderChain() {
        AccessTokenProvider accessTokenProvider = new AccessTokenProviderChain(Collections.<AccessTokenProvider>emptyList());
        restTemplate.setAccessTokenProvider(accessTokenProvider);
        restTemplate.setClockSkew(5);
        Field field = ReflectionUtils.findField(accessTokenProvider.getClass(), "clockSkew");
        field.setAccessible(true);
        assertEquals(5, ReflectionUtils.getField(field, accessTokenProvider));
    }

    // gh-1909
    @Test
    void testApplyClockSkewOnProvidedAccessTokenProviderChain() {
        AccessTokenProvider accessTokenProvider = new AccessTokenProviderChain(Collections.<AccessTokenProvider>emptyList());
        restTemplate.setClockSkew(5);
        restTemplate.setAccessTokenProvider(accessTokenProvider);
        Field field = ReflectionUtils.findField(accessTokenProvider.getClass(), "clockSkew");
        field.setAccessible(true);
        assertEquals(5, ReflectionUtils.getField(field, accessTokenProvider));
    }

    // gh-1909
    @Test
    void testClockSkewPropagationSkippedForNonAccessTokenProviderChainInstances() {
        restTemplate.setClockSkew(5);
        restTemplate.setAccessTokenProvider(null);
        restTemplate.setClockSkew(5);
        restTemplate.setAccessTokenProvider(new StubAccessTokenProvider());
        restTemplate.setClockSkew(5);
    }

    @Test
    void testTokenIsResetIfInvalid() throws Exception {
        DefaultOAuth2AccessToken token = new DefaultOAuth2AccessToken("TEST");
        token.setExpiration(new Date(System.currentTimeMillis() - 1000));
        restTemplate.getOAuth2ClientContext().setAccessToken(token);
        restTemplate.setAccessTokenProvider(new StubAccessTokenProvider() {

            @Override
            public OAuth2AccessToken obtainAccessToken(OAuth2ProtectedResourceDetails details, AccessTokenRequest parameters) throws UserRedirectRequiredException, AccessDeniedException {
                throw new UserRedirectRequiredException("https://www.foo.com/", Collections.<String, String>emptyMap());
            }
        });
        try {
            OAuth2AccessToken newToken = restTemplate.getAccessToken();
            assertNotNull(newToken);
            fail("Expected UserRedirectRequiredException");
        } catch (UserRedirectRequiredException e) {
            // planned
        }
        // context token should be reset as it clearly is invalid at this point
        assertNull(restTemplate.getOAuth2ClientContext().getAccessToken());
    }

    private final class SimpleResponseExtractor implements ResponseExtractor<Boolean> {

        public Boolean extractData(ClientHttpResponse response) throws IOException {
            return true;
        }
    }

    private static class NullRequestCallback implements RequestCallback {

        public void doWithRequest(ClientHttpRequest request) throws IOException {
        }
    }

    private static class StubAccessTokenProvider implements AccessTokenProvider {

        public OAuth2AccessToken obtainAccessToken(OAuth2ProtectedResourceDetails details, AccessTokenRequest parameters) throws UserRedirectRequiredException, AccessDeniedException {
            return new DefaultOAuth2AccessToken("FOO");
        }

        public boolean supportsRefresh(OAuth2ProtectedResourceDetails resource) {
            return false;
        }

        public OAuth2AccessToken refreshAccessToken(OAuth2ProtectedResourceDetails resource, OAuth2RefreshToken refreshToken, AccessTokenRequest request) throws UserRedirectRequiredException {
            return null;
        }

        public boolean supportsResource(OAuth2ProtectedResourceDetails resource) {
            return true;
        }
    }
}
