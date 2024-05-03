package org.springframework.security.aot;

import com.webauthn4j.WebAuthnManager;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.aot.hint.MemberCategory;
import org.springframework.aot.hint.RuntimeHints;
import org.springframework.aot.hint.RuntimeHintsRegistrar;
import org.springframework.aot.hint.TypeReference;
import org.springframework.context.annotation.ClassPathScanningCandidateComponentProvider;
import org.springframework.core.io.ClassPathResource;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.http.converter.json.MappingJackson2HttpMessageConverter;
import org.springframework.security.web.webauthn.registration.WebAuthnRegistrationFilter;
import org.springframework.security.webauthn.api.*;
import org.springframework.util.StringUtils;

import java.io.Serializable;
import java.util.HashSet;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * @author Josh Long
 * @author Daniel Garnier-Moiroux
 */
public class WebauthnRuntimeHintsRegistrar implements RuntimeHintsRegistrar {

	private final Log log = LogFactory.getLog(getClass());

	private static Set<TypeReference> findClassesInPackage(String packageName) {
		var classPathScanningCandidateComponentProvider = new ClassPathScanningCandidateComponentProvider(false);
		classPathScanningCandidateComponentProvider.addIncludeFilter((metadataReader, metadataReaderFactory) -> true);
		return classPathScanningCandidateComponentProvider//
			.findCandidateComponents(packageName)//
			.stream()//
			.map(bd -> TypeReference.of(Objects.requireNonNull(bd.getBeanClassName())))//
			.collect(Collectors.toUnmodifiableSet());
	}

	@Override
	public void registerHints(RuntimeHints hints, ClassLoader classLoader) {

		log.info("running the AOT hints for WebAuthn!");
		var typeReferenceHashSet = new HashSet<>(findClassesInPackage(WebAuthnManager.class.getPackageName()));

		hints.resources()
			.registerResource(new ClassPathResource("/META-INF/services/com.fasterxml.jackson.databind.Module"));

		var classes = """
				org.springframework.security.access.expression.AbstractSecurityExpressionHandler
				org.springframework.security.access.expression.SecurityExpressionHandler
				org.springframework.security.authentication.AnonymousAuthenticationProvider
				org.springframework.security.authentication.AuthenticationEventPublisher
				org.springframework.security.authentication.AuthenticationManager
				org.springframework.security.authentication.AuthenticationManagerResolver
				org.springframework.security.authentication.AuthenticationProvider
				org.springframework.security.authentication.DefaultAuthenticationEventPublisher
				org.springframework.security.authentication.ProviderManager
				org.springframework.security.authentication.ReactiveAuthenticationManager
				org.springframework.security.authentication.event.AuthenticationFailureBadCredentialsEvent
				org.springframework.security.authentication.event.AuthenticationFailureCredentialsExpiredEvent
				org.springframework.security.authentication.event.AuthenticationFailureDisabledEvent
				org.springframework.security.authentication.event.AuthenticationFailureExpiredEvent
				org.springframework.security.authentication.event.AuthenticationFailureLockedEvent
				org.springframework.security.authentication.event.AuthenticationFailureProviderNotFoundEvent
				org.springframework.security.authentication.event.AuthenticationFailureProxyUntrustedEvent
				org.springframework.security.authentication.event.AuthenticationFailureServiceExceptionEvent
				org.springframework.security.authorization.AuthorizationManager
				org.springframework.security.config.annotation.AbstractConfiguredSecurityBuilder
				org.springframework.security.config.annotation.AbstractSecurityBuilder
				org.springframework.security.config.annotation.ObjectPostProcessor
				org.springframework.security.config.annotation.SecurityBuilder
				org.springframework.security.config.annotation.SecurityConfigurer
				org.springframework.security.config.annotation.authentication.ProviderManagerBuilder
				org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder
				org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration
				org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration$AuthenticationManagerDelegator
				org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration$DefaultPasswordEncoderAuthenticationManagerBuilder
				org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration$EnableGlobalAuthenticationAutowiredConfigurer
				org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration$LazyPasswordEncoder
				org.springframework.security.config.annotation.authentication.configuration.EnableGlobalAuthentication
				org.springframework.security.config.annotation.authentication.configuration.GlobalAuthenticationConfigurerAdapter
				org.springframework.security.config.annotation.authentication.configuration.InitializeAuthenticationProviderBeanManagerConfigurer
				org.springframework.security.config.annotation.authentication.configuration.InitializeUserDetailsBeanManagerConfigurer
				org.springframework.security.config.annotation.configuration.AutowireBeanFactoryObjectPostProcessor
				org.springframework.security.config.annotation.configuration.ObjectPostProcessorConfiguration
				org.springframework.security.config.annotation.web.HttpSecurityBuilder
				org.springframework.security.config.annotation.web.builders.HttpSecurity
				org.springframework.security.config.annotation.web.builders.WebSecurity
				org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
				org.springframework.security.config.annotation.web.configuration.HttpSecurityConfiguration
				org.springframework.security.config.annotation.web.configuration.HttpSecurityConfiguration$DefaultPasswordEncoderAuthenticationManagerBuilder
				org.springframework.security.config.annotation.web.configuration.HttpSecurityConfiguration$LazyPasswordEncoder
				org.springframework.security.config.annotation.web.configuration.OAuth2ImportSelector
				org.springframework.security.config.annotation.web.configuration.SpringWebMvcImportSelector
				org.springframework.security.config.annotation.web.configuration.WebMvcSecurityConfiguration
				org.springframework.security.config.annotation.web.configuration.WebMvcSecurityConfiguration$1
				org.springframework.security.config.annotation.web.configuration.WebMvcSecurityConfiguration$CompositeFilterChainProxy
				org.springframework.security.config.annotation.web.configuration.WebMvcSecurityConfiguration$HandlerMappingIntrospectorCacheFilterFactoryBean
				org.springframework.security.config.annotation.web.configuration.WebSecurityConfiguration
				org.springframework.security.config.annotation.web.configuration.WebSecurityConfiguration$AnnotationAwareOrderComparator
				org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity
				org.springframework.security.config.crypto.RsaKeyConversionServicePostProcessor
				org.springframework.security.config.http.SessionCreationPolicy
				org.springframework.security.context.DelegatingApplicationListener
				org.springframework.security.core.Authentication
				org.springframework.security.core.userdetails.UserDetailsPasswordService
				org.springframework.security.core.userdetails.UserDetailsService
				org.springframework.security.crypto.password.PasswordEncoder
				org.springframework.security.data.repository.query.SecurityEvaluationContextExtension
				org.springframework.security.oauth2.client.registration.ClientRegistration
				org.springframework.security.oauth2.client.registration.ClientRegistrationRepository
				org.springframework.security.oauth2.jwt.JwtDecoder
				org.springframework.security.oauth2.server.authorization.OAuth2Authorization
				org.springframework.security.oauth2.server.resource.BearerTokenError
				org.springframework.security.oauth2.server.resource.authentication.BearerTokenAuthenticationToken
				org.springframework.security.oauth2.server.resource.introspection.OpaqueTokenIntrospector
				org.springframework.security.oauth2.server.resource.introspection.ReactiveOpaqueTokenIntrospector
				org.springframework.security.provisioning.InMemoryUserDetailsManager
				org.springframework.security.provisioning.UserDetailsManager
				org.springframework.security.rsocket.core.SecuritySocketAcceptorInterceptor
				org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrationRepository
				org.springframework.security.web.AuthenticationEntryPoint
				org.springframework.security.web.DefaultSecurityFilterChain
				org.springframework.security.web.FilterChainProxy
				org.springframework.security.web.SecurityFilterChain
				org.springframework.security.web.access.AuthorizationManagerWebInvocationPrivilegeEvaluator$HttpServletRequestTransformer
				org.springframework.security.web.access.ExceptionTranslationFilter
				org.springframework.security.web.access.HandlerMappingIntrospectorRequestTransformer
				org.springframework.security.web.access.RequestMatcherDelegatingWebInvocationPrivilegeEvaluator
				org.springframework.security.web.access.WebInvocationPrivilegeEvaluator
				org.springframework.security.web.access.expression.DefaultWebSecurityExpressionHandler
				org.springframework.security.web.access.intercept.AuthorizationFilter
				org.springframework.security.web.access.intercept.RequestMatcherDelegatingAuthorizationManager
				org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter
				org.springframework.security.web.authentication.HttpMessageConverterAuthenticationSuccessHandler$AuthenticationSuccess
				org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint
				org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter
				org.springframework.security.web.authentication.logout.LogoutFilter
				org.springframework.security.web.authentication.logout.LogoutHandler
				org.springframework.security.web.authentication.logout.LogoutSuccessEventPublishingLogoutHandler
				org.springframework.security.web.authentication.session.AbstractSessionFixationProtectionStrategy
				org.springframework.security.web.authentication.session.ChangeSessionIdAuthenticationStrategy
				org.springframework.security.web.authentication.session.CompositeSessionAuthenticationStrategy
				org.springframework.security.web.authentication.session.SessionAuthenticationStrategy
				org.springframework.security.web.authentication.ui.DefaultLoginPageGeneratingFilter
				org.springframework.security.web.context.AbstractSecurityWebApplicationInitializer
				org.springframework.security.web.context.SecurityContextHolderFilter
				org.springframework.security.web.csrf.CsrfFilter
				org.springframework.security.web.header.HeaderWriterFilter
				org.springframework.security.web.savedrequest.RequestCacheAwareFilter
				org.springframework.security.web.server.csrf.CsrfToken
				org.springframework.security.web.servlet.support.csrf.CsrfRequestDataValueProcessor
				org.springframework.security.web.servlet.util.matcher.MvcRequestMatcher
				org.springframework.security.web.servletapi.SecurityContextHolderAwareRequestFilter
				org.springframework.security.web.util.matcher.RequestMatcher
				org.springframework.security.web.util.matcher.RequestVariablesExtractor
				org.springframework.security.web.webauthn.authentication.WebAuthnAuthenticationFilter
				org.springframework.security.web.webauthn.registration.WebAuthnRegistrationFilter$SuccessfulUserRegistrationResponse
				org.springframework.security.web.webauthn.registration.WebAuthnRegistrationFilter$WebAuthnRegistrationRequest
				org.springframework.security.webauthn.api.AuthenticatorAssertionResponse$AuthenticatorAssertionResponseBuilder
				org.springframework.security.webauthn.api.AuthenticatorAttachment
				org.springframework.security.webauthn.api.AuthenticatorSelectionCriteria
				org.springframework.security.webauthn.api.Base64Url
				org.springframework.security.webauthn.api.PublicKeyCredential
				org.springframework.security.webauthn.api.PublicKeyCredential$PublicKeyCredentialBuilder
				org.springframework.security.webauthn.api.PublicKeyCredentialCreationOptions
				org.springframework.security.webauthn.api.PublicKeyCredentialParameters
				org.springframework.security.webauthn.api.PublicKeyCredentialRequestOptions
				org.springframework.security.webauthn.api.PublicKeyCredentialRpEntity
				org.springframework.security.webauthn.api.PublicKeyCredentialUserEntity
				org.springframework.security.webauthn.jackson.AttestationConveyancePreferenceSerializer
				org.springframework.security.webauthn.jackson.AuthenticationExtensionsClientInputsSerializer
				org.springframework.security.webauthn.jackson.AuthenticationExtensionsClientOutputsDeserializer
				org.springframework.security.webauthn.jackson.AuthenticatorAssertionResponseMixin$AuthenticatorAssertionResponseBuilderMixin
				org.springframework.security.webauthn.jackson.AuthenticatorAttachmentDeserializer
				org.springframework.security.webauthn.jackson.AuthenticatorAttachmentSerializer
				org.springframework.security.webauthn.jackson.AuthenticatorAttestationResponseMixin$AuthenticatorAttestationResponseBuilderMixin
				org.springframework.security.webauthn.jackson.AuthenticatorSelectionCriteriaMixin
				org.springframework.security.webauthn.jackson.AuthenticatorTransportDeserializer
				org.springframework.security.webauthn.jackson.Base64Serializer
				org.springframework.security.webauthn.jackson.Base64UrlMixin
				org.springframework.security.webauthn.jackson.COSEAlgorithmIdentifierDeserializer
				org.springframework.security.webauthn.jackson.COSEAlgorithmIdentifierSerializer
				org.springframework.security.webauthn.jackson.DurationSerializer
				org.springframework.security.webauthn.jackson.PublicKeyCredentialCreationOptionsMixin
				org.springframework.security.webauthn.jackson.PublicKeyCredentialMixin$PublicKeyCredentialBuilderMixin
				org.springframework.security.webauthn.jackson.PublicKeyCredentialRequestOptionsMixin
				org.springframework.security.webauthn.jackson.PublicKeyCredentialTypeDeserializer
				org.springframework.security.webauthn.jackson.PublicKeyCredentialTypeSerializer
				org.springframework.security.webauthn.jackson.RelyingPartyPublicKeyMixin
				org.springframework.security.webauthn.jackson.ResidentKeyRequirementSerializer
				org.springframework.security.webauthn.jackson.UserVerificationRequirementSerializer
				org.springframework.security.webauthn.management.RelyingPartyPublicKey
				"""
			.split(System.lineSeparator());

		for (var c : classes) {
			if (StringUtils.hasText(c)) {
				var tr = TypeReference.of(c);
				typeReferenceHashSet.add(tr);
			}
		}

		typeReferenceHashSet.addAll(findClassesInPackage("org.springframework.security.webauthn"));
		typeReferenceHashSet.addAll(findClassesInPackage("org.springframework.security.web.webauthn"));

		var registrationSpecificClasses = Set
			.of(PublicKeyCredentialCreationOptions.class, AttestationConveyancePreference.class,
					PublicKeyCredentialUserEntity.class, Base64Url.class, PublicKeyCredentialParameters.class,
					PublicKeyCredentialDescriptor.class, AuthenticatorSelectionCriteria.class,
					AuthenticationExtensionsClientInputs.class, PublicKeyCredentialRpEntity.class,
					COSEAlgorithmIdentifier.class, PublicKeyCredentialType.class,
					AuthenticatorAttestationResponse.AuthenticatorAttestationResponseBuilder.class,
					AuthenticatorTransport.class, AuthenticatorAttestationResponse.class, PublicKeyCredential.class,
					HttpMessageConverter.class, MappingJackson2HttpMessageConverter.class,
					WebAuthnRegistrationFilter.SuccessfulUserRegistrationResponse.class,
					com.webauthn4j.data.attestation.authenticator.AttestedCredentialData.class,
					WebAuthnRegistrationFilter.WebAuthnRegistrationRequest.class)
			.stream()
			.map(TypeReference::of)
			.toList();

		typeReferenceHashSet.addAll(registrationSpecificClasses);

		var mcs = MemberCategory.values();
		for (var tr : typeReferenceHashSet) {
			hints.reflection().registerType(tr, mcs);

			var message = ("registering " + tr.getName() + " for reflection");

			try {
				if (StringUtils.hasText(tr.getName())) {
					var clzz = Class.forName(tr.getName());
					var isSerializable = Serializable.class.isAssignableFrom(clzz);
					if (isSerializable) {
						hints.serialization().registerType(tr);
						message += (" and registering for serialization");
					}
				}
			} //
			catch (Throwable throwable) {
				// don't care
				// log.trace("issue trying to register " + tr.getName(), throwable);
			}
			log.info(message);

		}

	}

}