/*
 * Copyright 2002-2024 the original author or authors.
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

package org.springframework.security.webauthn.jackson;

import com.fasterxml.jackson.core.JacksonException;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonToken;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.deser.std.StdDeserializer;
import org.springframework.security.webauthn.api.*;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

/**
 * Provides Jackson deserialization of {@link AuthenticationExtensionsClientOutputs}.
 *
 * @since 6.3
 * @author Rob Winch
 */
class AuthenticationExtensionsClientOutputsDeserializer extends StdDeserializer<AuthenticationExtensionsClientOutputs> {

	/**
	 * Creates a new instance.
	 */
	AuthenticationExtensionsClientOutputsDeserializer() {
		super(AuthenticationExtensionsClientOutputs.class);
	}

	@Override
	public AuthenticationExtensionsClientOutputs deserialize(JsonParser parser, DeserializationContext ctxt)
			throws IOException, JacksonException {
		List<AuthenticationExtensionsClientOutput<?>> outputs = new ArrayList<>();
		for (String key = parser.nextFieldName(); key != null; key = parser.nextFieldName()) {
			JsonToken startObject = parser.nextValue();
			if (startObject != JsonToken.START_OBJECT) {
				ctxt.handleUnexpectedToken(AuthenticationExtensionsClientOutputs.class, parser);
			}
			if (CredentialPropertiesOutput.EXTENSION_ID.equals(key)) {
				CredentialPropertiesOutput output = parser.readValueAs(CredentialPropertiesOutput.class);
				outputs.add(output);
			}
			else {
				throw new IllegalArgumentException("Cannot process extension with id " + key);
			}
			JsonToken endObject = parser.nextValue();
			if (endObject != JsonToken.END_OBJECT) {
				ctxt.handleUnexpectedToken(AuthenticationExtensionsClientOutputs.class, parser);
			}
		}

		return new ImmutableAuthenticationExtensionsClientOutputs(outputs);
	}

}
