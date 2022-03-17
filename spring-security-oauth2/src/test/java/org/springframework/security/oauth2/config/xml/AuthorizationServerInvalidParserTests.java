package org.springframework.security.oauth2.config.xml;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.parsing.BeanDefinitionParsingException;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.context.support.GenericXmlApplicationContext;
import org.springframework.security.oauth2.provider.CompositeTokenGranter;
import org.springframework.security.oauth2.provider.TokenGranter;

class AuthorizationServerInvalidParserTests {

    private static String RESOURCE_NAME = "authorization-server-invalid.xml";

    private ConfigurableApplicationContext context;

    @Test
    void testCustomGrantRegistered() {
        BeanDefinitionParsingException e = Assertions.assertThrows(BeanDefinitionParsingException.class, () -> {
            context = new GenericXmlApplicationContext(getClass(), RESOURCE_NAME);
            TokenGranter granter = context.getBean(CompositeTokenGranter.class);
            assertNotNull(granter);
        });
        assertTrue(e.getMessage().contains("Configuration problem: ClientDetailsService must be provided"));
    }
}
