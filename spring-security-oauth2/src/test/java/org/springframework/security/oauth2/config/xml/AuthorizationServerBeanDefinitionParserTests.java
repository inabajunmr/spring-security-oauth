/*
 * Copyright 2006-2011 the original author or authors.
 * 
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 * 
 * https://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
 * an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 */
package org.springframework.security.oauth2.config.xml;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.springframework.context.support.GenericXmlApplicationContext;
import org.springframework.security.oauth2.provider.endpoint.FrameworkEndpointHandlerMapping;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.*;
import static org.junit.jupiter.params.provider.Arguments.arguments;

/**
 * @author Dave Syer
 */
class AuthorizationServerBeanDefinitionParserTests {

    private static final String CHECK_TOKEN_CUSTOM_ENDPOINT_RESOURCE = "authorization-server-check-token-custom-endpoint";


    public static Stream<Arguments> parameters() {
        return Stream.of(arguments( "authorization-server-vanilla" ), arguments( "authorization-server-extras" ), arguments( "authorization-server-types" ), arguments( "authorization-server-check-token"), arguments( "authorization-server-disable" ), arguments( CHECK_TOKEN_CUSTOM_ENDPOINT_RESOURCE ));
    }

    @ParameterizedTest
    @MethodSource("parameters")
    void testDefaults(String resource) {
        GenericXmlApplicationContext context = new GenericXmlApplicationContext(getClass(), resource + ".xml");
        assertTrue(context.containsBeanDefinition("oauth2AuthorizationEndpoint"));
        context.close();
    }

    @ParameterizedTest
    @MethodSource("parameters")
    void testCheckTokenCustomEndpoint(String resource) {
        GenericXmlApplicationContext context = new GenericXmlApplicationContext(getClass(), resource + ".xml");
        if (!CHECK_TOKEN_CUSTOM_ENDPOINT_RESOURCE.equals(resource)) {
            return;
        }
        FrameworkEndpointHandlerMapping frameworkEndpointHandlerMapping = context.getBean(FrameworkEndpointHandlerMapping.class);
        assertNotNull(frameworkEndpointHandlerMapping);
        assertEquals("/custom_check_token", frameworkEndpointHandlerMapping.getPath("/oauth/check_token"));
        context.close();
    }
}
