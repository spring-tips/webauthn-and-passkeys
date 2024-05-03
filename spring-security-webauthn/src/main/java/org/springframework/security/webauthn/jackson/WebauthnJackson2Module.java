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

import com.fasterxml.jackson.core.Version;
import com.fasterxml.jackson.databind.module.SimpleModule;
import org.springframework.security.webauthn.api.AuthenticatorAssertionResponse;
import org.springframework.security.webauthn.api.PublicKeyCredentialRequestOptions;
import org.springframework.security.webauthn.api.Base64Url;
import org.springframework.security.webauthn.api.Base64Url;
import org.springframework.security.webauthn.api.*;
import org.springframework.security.webauthn.management.RelyingPartyPublicKey;

/**
 * Adds Jackson support for Spring Security WebAuthn. It is automatically registered when
 * using Jackson's SPI support.
 *
 * @since 6.3
 * @author Rob Winch
 */
public class WebauthnJackson2Module extends SimpleModule {

	/**
	 * Creates a new instance.
	 */
	public WebauthnJackson2Module() {
		super(WebauthnJackson2Module.class.getName(), new Version(1, 0, 0, null, null, null));
	}

	@Override
	public void setupModule(SetupContext context) {
		context.setMixInAnnotations(Base64Url.class, Base64UrlMixin.class);
		context.setMixInAnnotations(AttestationConveyancePreference.class, AttestationConveyancePreferenceMixin.class);
		context.setMixInAnnotations(AuthenticationExtensionsClientInputs.class,
				AuthenticationExtensionsClientInputsMixin.class);
		context.setMixInAnnotations(AuthenticationExtensionsClientOutputs.class,
				AuthenticationExtensionsClientOutputsMixin.class);
		context.setMixInAnnotations(AuthenticatorAssertionResponse.AuthenticatorAssertionResponseBuilder.class,
				AuthenticatorAssertionResponseMixin.AuthenticatorAssertionResponseBuilderMixin.class);
		context.setMixInAnnotations(AuthenticatorAssertionResponse.class, AuthenticatorAssertionResponseMixin.class);
		context.setMixInAnnotations(AuthenticatorAttachment.class, AuthenticatorAttachmentMixin.class);
		context.setMixInAnnotations(AuthenticatorAttestationResponse.class,
				AuthenticatorAttestationResponseMixin.class);
		context.setMixInAnnotations(AuthenticatorAttestationResponse.AuthenticatorAttestationResponseBuilder.class,
				AuthenticatorAttestationResponseMixin.AuthenticatorAttestationResponseBuilderMixin.class);
		context.setMixInAnnotations(AuthenticatorSelectionCriteria.class, AuthenticatorSelectionCriteriaMixin.class);
		context.setMixInAnnotations(AuthenticatorTransport.class, AuthenticatorTransportMixin.class);
		context.setMixInAnnotations(COSEAlgorithmIdentifier.class, COSEAlgorithmIdentifierMixin.class);
		context.setMixInAnnotations(CredentialPropertiesOutput.class, CredentialPropertiesOutputMixin.class);
		context.setMixInAnnotations(PublicKeyCredential.PublicKeyCredentialBuilder.class,
				PublicKeyCredentialMixin.PublicKeyCredentialBuilderMixin.class);
		context.setMixInAnnotations(PublicKeyCredential.class, PublicKeyCredentialMixin.class);
		context.setMixInAnnotations(PublicKeyCredentialCreationOptions.class,
				PublicKeyCredentialCreationOptionsMixin.class);
		context.setMixInAnnotations(PublicKeyCredentialRequestOptions.class,
				PublicKeyCredentialRequestOptionsMixin.class);
		context.setMixInAnnotations(PublicKeyCredentialType.class, PublicKeyCredentialTypeMixin.class);
		context.setMixInAnnotations(RelyingPartyPublicKey.class, RelyingPartyPublicKeyMixin.class);
		context.setMixInAnnotations(ResidentKeyRequirement.class, ResidentKeyRequirementMixin.class);
		context.setMixInAnnotations(UserVerificationRequirement.class, UserVerificationRequirementMixin.class);
	}

}
