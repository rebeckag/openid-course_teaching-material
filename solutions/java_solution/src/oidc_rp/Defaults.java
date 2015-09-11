package oidc_rp;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.SerializeException;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.client.ClientRegistrationErrorResponse;
import com.nimbusds.oauth2.sdk.client.ClientRegistrationResponse;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.openid.connect.sdk.ClaimsRequest;
import com.nimbusds.openid.connect.sdk.OIDCResponseTypeValue;
import com.nimbusds.openid.connect.sdk.claims.ClaimRequirement;
import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientInformation;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientInformationResponse;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientMetadata;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientRegistrationRequest;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientRegistrationResponseParser;

public class Defaults {
	public static class AuthReqParams {

		public URI redirectURI;
		public Scope scope;
		public ResponseType respType;
		public ClaimsRequest claimsReq;

		public AuthReqParams(String redirectURI, String scope, ResponseType rt,
				ClaimsRequest cr) {
			try {
				this.redirectURI = new URI(redirectURI);
			} catch (URISyntaxException e) {
			}
			this.scope = Scope.parse(scope);
			this.respType = rt;
			this.claimsReq = cr;
		}

	}

	public enum AuthReqDefault {
		CODE_FLOW, IMPLICIT_FLOW, HYBRID_FLOW, // auth flows
		CLAIMS_BY_SCOPE, CLAIMS_REQUEST, // claims
		SCOPE_BEHAVIOR // special behavior
	}

	public enum RegistrationReqDefault {
		DYNAMIC, STATIC, // static/dynamic registration
		USERINFO_SIGNED, USERINFO_ENCRYPTED, USERINFO_SIGNED_ENCRYPTED // userinfo
																		// sign/encrypt
	}

	public static AuthReqParams getDefaultForAuthReq(AuthReqDefault d) {
		switch (d) {
		case CODE_FLOW:
			return new AuthReqParams(
					"http://localhost:8090/code_flow_callback", "openid",
					new ResponseType(ResponseType.Value.CODE), null);
		case IMPLICIT_FLOW:
			return new AuthReqParams(
					"http://localhost:8090/implicit_flow_callback", "openid",
					new ResponseType(OIDCResponseTypeValue.ID_TOKEN,
							ResponseType.Value.TOKEN), null);
		case HYBRID_FLOW:
			return new AuthReqParams(
					"http://localhost:8090/implicit_flow_callback", "openid",
					new ResponseType(ResponseType.Value.CODE,
							OIDCResponseTypeValue.ID_TOKEN), null);
		case CLAIMS_BY_SCOPE:
			return new AuthReqParams(
					"http://localhost:8090/code_flow_callback",
					"openid profile",
					new ResponseType(ResponseType.Value.CODE), null);
		case CLAIMS_REQUEST:
			return new AuthReqParams(
					"http://localhost:8090/code_flow_callback", "openid",
					new ResponseType(ResponseType.Value.CODE),
					Defaults.getClaimsReq());
		case SCOPE_BEHAVIOR:
			return new AuthReqParams(
					"http://localhost:8090/code_flow_callback",
					"openid who_am_i",
					new ResponseType(ResponseType.Value.CODE), null);
		}

		return null;
	}

	public static OIDCClientInformation getDefaultForRegistrationReq(
			OIDCClientMetadata metadata, OIDCProviderMetadata providerMetadata,
			RegistrationReqDefault d) throws ParseException,
			SerializeException, IOException {
		switch (d) {
		case DYNAMIC:
			return doClientRegistration(metadata, providerMetadata);
		case STATIC:
			return new OIDCClientInformation(new ClientID("TODO"), null,
					metadata, new Secret("TODO"));
		case USERINFO_SIGNED:
			metadata.setUserInfoJWSAlg(new JWSAlgorithm("RS256"));
			return doClientRegistration(metadata, providerMetadata);
		case USERINFO_ENCRYPTED:
			metadata.setUserInfoJWEEnc(new EncryptionMethod("RSA1_5"));
			metadata.setUserInfoJWEAlg(new JWEAlgorithm("A128CBC-HS256"));
			return doClientRegistration(metadata, providerMetadata);
		case USERINFO_SIGNED_ENCRYPTED:
			metadata.setUserInfoJWSAlg(new JWSAlgorithm("RS256"));
			metadata.setUserInfoJWEEnc(new EncryptionMethod("RSA1_5"));
			metadata.setUserInfoJWEAlg(new JWEAlgorithm("A128CBC-HS256"));
			return doClientRegistration(metadata, providerMetadata);
		}

		return null;
	}

	private static ClaimsRequest getClaimsReq() {
		ClaimsRequest claimsReq = new ClaimsRequest();
		claimsReq.addUserInfoClaim("given_name", ClaimRequirement.ESSENTIAL);
		claimsReq.addUserInfoClaim("family_name", ClaimRequirement.ESSENTIAL);
		claimsReq.addUserInfoClaim("nickname");
		claimsReq.addIDTokenClaim("email", ClaimRequirement.ESSENTIAL);
		claimsReq.addIDTokenClaim("phone_number");

		return claimsReq;
	}

	private static OIDCClientInformation doClientRegistration(
			OIDCClientMetadata metadata, OIDCProviderMetadata providerMetadata)
			throws ParseException, SerializeException, IOException {
		// Make registration request
		OIDCClientRegistrationRequest registrationRequest = new OIDCClientRegistrationRequest(
				providerMetadata.getRegistrationEndpointURI(), metadata, null);
		HTTPResponse regHTTPResponse = registrationRequest.toHTTPRequest()
				.send();

		// Parse and check response
		ClientRegistrationResponse registrationResponse = OIDCClientRegistrationResponseParser
				.parse(regHTTPResponse);

		if (registrationResponse instanceof ClientRegistrationErrorResponse) {
			ErrorObject error = ((ClientRegistrationErrorResponse) registrationResponse)
					.getErrorObject();
			// TODO error handling
			System.err.println(error.getCode() + ": " + error.getDescription());
			System.exit(-1);
		}

		// Store client information from OP
		OIDCClientInformation clientInformation = ((OIDCClientInformationResponse) registrationResponse)
				.getOIDCClientInformation();
		return clientInformation;
	}
}
