package org.springframework.security.oauth2.config.xml;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.security.oauth2.client.OAuth2RestTemplate;
import org.springframework.security.oauth2.client.resource.OAuth2ProtectedResourceDetails;
import org.springframework.security.oauth2.client.token.grant.client.ClientCredentialsResourceDetails;
import org.springframework.security.oauth2.client.token.grant.code.AuthorizationCodeResourceDetails;
import org.springframework.security.oauth2.client.token.grant.implicit.ImplicitResourceDetails;
import org.springframework.security.oauth2.client.token.grant.password.ResourceOwnerPasswordResourceDetails;
import org.springframework.security.oauth2.common.AuthenticationScheme;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

@ContextConfiguration
@ExtendWith(SpringExtension.class)
class ResourceBeanDefinitionParserTests {

    @Autowired
    @Qualifier("one")
    private OAuth2ProtectedResourceDetails one;

    @Autowired
    @Qualifier("two")
    private OAuth2ProtectedResourceDetails two;

    @Autowired
    @Qualifier("three")
    private AuthorizationCodeResourceDetails three;

    @Autowired
    @Qualifier("four")
    private ImplicitResourceDetails four;

    @Autowired
    @Qualifier("five")
    private ClientCredentialsResourceDetails five;

    @Autowired
    @Qualifier("six")
    private AuthorizationCodeResourceDetails six;

    @Autowired
    @Qualifier("seven")
    private ResourceOwnerPasswordResourceDetails seven;

    @Autowired
    @Qualifier("template")
    private OAuth2RestTemplate template;

    @Test
    void testResourceFromNonPropertyFile() {
        assertEquals("my-client-id-non-property-file", one.getClientId());
        assertEquals("my-client-secret-non-property-file", one.getClientSecret());
        assertEquals("https://somewhere.com", one.getAccessTokenUri());
        assertEquals(2, one.getScope().size());
        assertEquals("[none, some]", one.getScope().toString());
    }

    @Test
    void testResourceFromPropertyFile() {
        assertEquals("my-client-id-property-file", two.getClientId());
        assertEquals("my-client-secret-property-file", two.getClientSecret());
        assertEquals("https://myhost.com", two.getAccessTokenUri());
        assertEquals(2, two.getScope().size());
        assertEquals("[none, all]", two.getScope().toString());
    }

    @Test
    void testResourceWithRedirectUri() {
        assertEquals("my-client-id", three.getClientId());
        assertNull(three.getClientSecret());
        assertEquals("https://somewhere.com", three.getAccessTokenUri());
        assertEquals("https://anywhere.com", three.getPreEstablishedRedirectUri());
        assertFalse(three.isUseCurrentUri());
    }

    @Test
    void testResourceWithImplicitGrant() {
        assertEquals("my-client-id", four.getClientId());
        assertNull(four.getClientSecret());
        assertEquals("https://somewhere.com", four.getUserAuthorizationUri());
    }

    @Test
    void testResourceWithClientCredentialsGrant() {
        assertEquals("my-secret-id", five.getClientId());
        assertEquals("secret", five.getClientSecret());
        assertEquals("https://somewhere.com", five.getAccessTokenUri());
        assertNotNull(template.getOAuth2ClientContext().getAccessTokenRequest());
    }

    @Test
    void testResourceWithCurrentUriHint() {
        assertEquals("my-client-id", six.getClientId());
        assertFalse(six.isUseCurrentUri());
        assertEquals(AuthenticationScheme.form, six.getClientAuthenticationScheme());
    }

    @Test
    void testResourceWithPasswordGrant() {
        assertEquals("my-client-id", seven.getClientId());
        assertEquals("secret", seven.getClientSecret());
        assertEquals("https://somewhere.com", seven.getAccessTokenUri());
        assertEquals("admin", seven.getUsername());
        assertEquals("long-and-strong", seven.getPassword());
    }
}
