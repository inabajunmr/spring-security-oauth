/*
 * Copyright 2011-2012 the original author or authors.
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
package org.springframework.security.oauth2.http.converter.jaxb;

import static org.mockito.Matchers.any;
import static org.mockito.Mockito.lenient;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.lang.reflect.Field;
import java.util.Date;
import javax.xml.bind.JAXBContext;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpInputMessage;
import org.springframework.http.HttpOutputMessage;
import org.springframework.http.MediaType;

/**
 * @author Rob Winch
 */
@ExtendWith(MockitoExtension.class)
abstract class BaseJaxbMessageConverterTest {

    protected static final String OAUTH_ACCESSTOKEN_NOEXPIRES = "<oauth><access_token>SlAV32hkKG</access_token></oauth>";

    protected static final String OAUTH_ACCESSTOKEN_NOREFRESH = "<oauth><access_token>SlAV32hkKG</access_token><expires_in>10</expires_in></oauth>";

    protected static final String OAUTH_ACCESSTOKEN = "<oauth><access_token>SlAV32hkKG</access_token><expires_in>10</expires_in><refresh_token>8xLOxBtZp8</refresh_token></oauth>";

    protected MediaType contentType;

    protected ByteArrayOutputStream output;

    @Mock
    protected Date expiration;

    @Mock
    protected HttpOutputMessage outputMessage;

    @Mock
    protected HttpInputMessage inputMessage;

    @Mock
    protected HttpHeaders headers;

    @Mock
    protected JAXBContext context;

    @BeforeEach
    final void setUp() throws Exception {
        long now = System.currentTimeMillis();
        lenient().when(expiration.before(any(Date.class))).thenReturn(false);
        lenient().when(expiration.getTime()).thenReturn(now + 10999);
        output = new ByteArrayOutputStream();
        contentType = MediaType.APPLICATION_XML;
        lenient().when(headers.getContentType()).thenReturn(contentType);
        lenient().when(outputMessage.getHeaders()).thenReturn(headers);
        lenient().when(outputMessage.getBody()).thenReturn(output);
    }

    protected InputStream createInputStream(String in) throws UnsupportedEncodingException {
        return new ByteArrayInputStream(in.getBytes("UTF-8"));
    }

    protected String getOutput() throws UnsupportedEncodingException {
        return output.toString("UTF-8");
    }

    protected void useMockJAXBContext(AbstractJaxbMessageConverter object, Class<?> jaxbClassToBeBound) throws Exception {
        JAXBContext jaxbContext = JAXBContext.newInstance(jaxbClassToBeBound);
        lenient().when(context.createMarshaller()).thenReturn(jaxbContext.createMarshaller());
        lenient().when(context.createUnmarshaller()).thenReturn(jaxbContext.createUnmarshaller());
        Field field = AbstractJaxbMessageConverter.class.getDeclaredField("context");
        field.setAccessible(true);
        field.set(object, context);
    }
}
