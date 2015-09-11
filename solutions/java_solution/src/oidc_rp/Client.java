package oidc_rp;

import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.util.Scanner;

import net.minidev.json.JSONArray;
import net.minidev.json.JSONObject;
import oidc_rp.Defaults.AuthReqDefault;
import oidc_rp.Defaults.RegistrationReqDefault;
import spark.Request;
import spark.Response;
import spark.Session;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.ReadOnlyJWTClaimsSet;
import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.AuthorizationCodeGrant;
import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.SerializeException;
import com.nimbusds.oauth2.sdk.TokenErrorResponse;
import com.nimbusds.oauth2.sdk.TokenRequest;
import com.nimbusds.oauth2.sdk.TokenResponse;
import com.nimbusds.oauth2.sdk.auth.ClientSecretBasic;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.oauth2.sdk.util.JSONObjectUtils;
import com.nimbusds.openid.connect.sdk.AuthenticationErrorResponse;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.AuthenticationResponse;
import com.nimbusds.openid.connect.sdk.AuthenticationResponseParser;
import com.nimbusds.openid.connect.sdk.AuthenticationSuccessResponse;
import com.nimbusds.openid.connect.sdk.Nonce;
import com.nimbusds.openid.connect.sdk.OIDCAccessTokenResponse;
import com.nimbusds.openid.connect.sdk.OIDCTokenResponseParser;
import com.nimbusds.openid.connect.sdk.UserInfoErrorResponse;
import com.nimbusds.openid.connect.sdk.UserInfoRequest;
import com.nimbusds.openid.connect.sdk.UserInfoResponse;
import com.nimbusds.openid.connect.sdk.UserInfoSuccessResponse;
import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientInformation;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientMetadata;
import com.nimbusds.openid.connect.sdk.util.DefaultJWTDecoder;

public class Client {
	// TODO specify the correct path
	public static Path FILE_DIR = Paths.get(".");

	private OIDCClientInformation clientInformation;
	private OIDCProviderMetadata providerMetadata;
	private Defaults.AuthReqParams authReqParams;

	public Client(String clientMetadataString, String issuer)
			throws ParseException, URISyntaxException, IOException,
			SerializeException {
		OIDCClientMetadata clientMetadata = OIDCClientMetadata
				.parse(JSONObjectUtils.parse(clientMetadataString));

		authReqParams = Defaults
				.getDefaultForAuthReq(AuthReqDefault.SCOPE_BEHAVIOR);

		providerMetadata = getProviderConfig(issuer);
		clientInformation = Defaults.getDefaultForRegistrationReq(
				clientMetadata, providerMetadata,
				RegistrationReqDefault.DYNAMIC);
	}

	private OIDCProviderMetadata getProviderConfig(String issuer)
			throws URISyntaxException, IOException, ParseException {
		URI issuerURI = new URI(issuer);
		URL providerConfigurationURL = issuerURI.resolve(
				"/.well-known/openid-configuration").toURL();
		InputStream stream = providerConfigurationURL.openStream();
		// Read all data from URL
		String providerInfo = null;
		try (java.util.Scanner s = new java.util.Scanner(stream)) {
			providerInfo = s.useDelimiter("\\A").hasNext() ? s.next() : "";
		}
		OIDCProviderMetadata providerMetadata = OIDCProviderMetadata
				.parse(providerInfo);
		return providerMetadata;
	}

	public String authenticate(Request req, Response res)
			throws URISyntaxException, SerializeException {
		// session object that can be used to store store state between requests
		Session session = req.session();
		String login_url = doAuthReq(session, authReqParams);
		res.redirect(login_url); // Redirect the user to the provider
		return null;
	}

	public String codeFlowCallback(Request req, Response res)
			throws IOException {
		// Callback redirect URI
		String url = req.url() + "?" + req.raw().getQueryString();

		// TODO parse authentication response from url
		AuthenticationSuccessResponse authResp = parseAuthResp(req.session(),
				url);

		// TODO make token request
		OIDCAccessTokenResponse accessTokenResp = doTokenReq(
				authResp.getAuthorizationCode(),
				req.session().attribute("redirect_uri"));
		// TODO verify the id token
		JWT idToken = accessTokenResp.getIDToken();
		// TODO make userinfo request
		UserInfoSuccessResponse userInfoClaims = doUserInfoReq(accessTokenResp
				.getAccessToken());
		ReadOnlyJWTClaimsSet idTokenClaims = null;
		try {
			idTokenClaims = verifyIdToken(idToken);
		} catch (ParseException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		// TODO set the appropriate values
		AuthorizationCode authCode = authResp.getAuthorizationCode();
		AccessToken accessToken = accessTokenResp.getAccessToken();
		String parsedIdToken = idToken.getParsedString();
		UserInfoSuccessResponse userInfoResponse = userInfoClaims;
		return WebServer.successPage(authCode, accessToken, parsedIdToken,
				idTokenClaims, userInfoResponse);
	}

	public String implicitFlowCallback(Request req, Response res)
			throws IOException {
		// Callback redirect URI
		String url = req.url() + "#" + req.queryParams("url_fragment");

		// TODO parse authentication response from url
		AuthenticationSuccessResponse authResp = parseAuthResp(req.session(),
				url);

		// TODO verify the id token
		JWT idToken = authResp.getIDToken();
		ReadOnlyJWTClaimsSet idTokenClaims = null;
		try {
			idTokenClaims = verifyIdToken(idToken);
		} catch (ParseException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		AuthorizationCode authCode = authResp.getAuthorizationCode();
		AccessToken accessToken = authResp.getAccessToken();
		String parsedIdToken = idToken.getParsedString();
		return WebServer.successPage(authCode, accessToken, parsedIdToken,
				idTokenClaims, null);
	}

	private String doAuthReq(Session session,
			Defaults.AuthReqParams authReqParams) throws SerializeException {
		session.attribute("redirect_uri", authReqParams.redirectURI);

		// Generate random state string for pairing the response to the request
		State state = new State();
		session.attribute("state", state);

		// Generate nonce
		Nonce nonce = new Nonce();
		session.attribute("nonce", nonce);

		// Compose the request
		AuthenticationRequest.Builder authenticationRequest = new AuthenticationRequest.Builder(
				authReqParams.respType, authReqParams.scope,
				clientInformation.getID(), authReqParams.redirectURI);

		authenticationRequest.state(state).nonce(nonce)
				.endpointURI(providerMetadata.getAuthorizationEndpointURI());
		if (authReqParams.claimsReq != null) {
			authenticationRequest.claims(authReqParams.claimsReq);
		}

		URI authReqURI = authenticationRequest.build().toURI();
		return authReqURI.toString();
	}

	private ReadOnlyJWTClaimsSet verifyIdToken(JWT idToken)
			throws ParseException {
		RSAPublicKey providerKey = null;
		try {
			JSONObject key = getProviderRSAJWK(providerMetadata.getJWKSetURI()
					.toURL().openStream());
			providerKey = RSAKey.parse(key).toRSAPublicKey();
		} catch (NoSuchAlgorithmException | InvalidKeySpecException
				| IOException | java.text.ParseException e) {
			// TODO error handling
		}

		DefaultJWTDecoder jwtDecoder = new DefaultJWTDecoder();
		jwtDecoder.addJWSVerifier(new RSASSAVerifier(providerKey));
		ReadOnlyJWTClaimsSet claims = null;
		try {
			claims = jwtDecoder.decodeJWT(idToken);
		} catch (JOSEException | java.text.ParseException e) {
			// TODO error handling
		}

		return claims;
	}

	private JSONObject getProviderRSAJWK(InputStream is) throws ParseException {
		// Read all data from stream
		StringBuilder sb = new StringBuilder();
		try (Scanner scanner = new Scanner(is);) {
			while (scanner.hasNext()) {
				sb.append(scanner.next());
			}
		}

		// Parse the data as json
		String jsonString = sb.toString();
		JSONObject json = JSONObjectUtils.parse(jsonString);

		// Find the RSA signing key
		JSONArray keyList = (JSONArray) json.get("keys");
		for (Object key : keyList) {
			JSONObject k = (JSONObject) key;
			if (k.get("use").equals("sig") && k.get("kty").equals("RSA")) {
				return k;
			}
		}
		return null;
	}

	private OIDCAccessTokenResponse doTokenReq(AuthorizationCode authCode,
			URI redirectURI) {
		TokenRequest tokenReq = new TokenRequest(
				providerMetadata.getTokenEndpointURI(), new ClientSecretBasic(
						clientInformation.getID(),
						clientInformation.getSecret()),
				new AuthorizationCodeGrant(authCode, redirectURI));

		HTTPResponse tokenHTTPResp = null;
		try {
			tokenHTTPResp = tokenReq.toHTTPRequest().send();
		} catch (SerializeException | IOException e) {
			// TODO proper error handling
		}

		// Parse and check response
		TokenResponse tokenResponse = null;
		try {
			tokenResponse = OIDCTokenResponseParser.parse(tokenHTTPResp);
		} catch (ParseException e) {
			// TODO proper error handling
		}

		if (tokenResponse instanceof TokenErrorResponse) {
			ErrorObject error = ((TokenErrorResponse) tokenResponse)
					.getErrorObject();
			System.err.println(error);
			System.exit(-1);
		}

		OIDCAccessTokenResponse accessTokenResponse = (OIDCAccessTokenResponse) tokenResponse;
		accessTokenResponse.getAccessToken();
		accessTokenResponse.getIDToken();
		return accessTokenResponse;
	}

	private UserInfoSuccessResponse doUserInfoReq(AccessToken accessToken) {
		UserInfoRequest userInfoReq = new UserInfoRequest(
				providerMetadata.getUserInfoEndpointURI(),
				(BearerAccessToken) accessToken);

		HTTPResponse userInfoHTTPResp = null;
		try {
			userInfoHTTPResp = userInfoReq.toHTTPRequest().send();
		} catch (SerializeException | IOException e) {
			// TODO proper error handling
		}

		UserInfoResponse userInfoResponse = null;
		try {
			userInfoResponse = UserInfoResponse.parse(userInfoHTTPResp);
		} catch (ParseException e) {
			// TODO proper error handling
		}

		if (userInfoResponse instanceof UserInfoErrorResponse) {
			ErrorObject error = ((UserInfoErrorResponse) userInfoResponse)
					.getErrorObject();
			// TODO error handling
		}

		UserInfoSuccessResponse successResponse = (UserInfoSuccessResponse) userInfoResponse;
		JSONObject claims = successResponse.getUserInfo().toJSONObject();
		return successResponse;
	}

	private AuthenticationSuccessResponse parseAuthResp(Session session,
			String url) {
		AuthenticationResponse authResp = null;
		try {
			authResp = AuthenticationResponseParser.parse(new URI(url));
		} catch (ParseException | URISyntaxException e) {
			// TODO error handling
		}

		if (authResp instanceof AuthenticationErrorResponse) {
			ErrorObject error = ((AuthenticationErrorResponse) authResp)
					.getErrorObject();
			System.err.println(error.getCode() + ": " + error.getDescription());
			System.exit(-1);
		}

		AuthenticationSuccessResponse successResponse = (AuthenticationSuccessResponse) authResp;

		// Don't forget to check the state
		if (!verifyState(session, successResponse.getState())) {
			// TODO proper error handling
		}

		AuthorizationCode authCode = successResponse.getAuthorizationCode();
		return successResponse;
	}

	private boolean verifyState(Session session, State actual) {
		State expected = session.attribute("state");
		return expected.equals(actual);
	}
}
