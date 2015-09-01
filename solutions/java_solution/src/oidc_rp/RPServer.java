package oidc_rp;

import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.text.MessageFormat;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.Scanner;
import java.util.logging.Logger;

import net.minidev.json.JSONArray;
import net.minidev.json.JSONObject;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.ReadOnlyJWTClaimsSet;
import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.AuthorizationCodeGrant;
import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.SerializeException;
import com.nimbusds.oauth2.sdk.TokenErrorResponse;
import com.nimbusds.oauth2.sdk.TokenRequest;
import com.nimbusds.oauth2.sdk.TokenResponse;
import com.nimbusds.oauth2.sdk.client.ClientRegistrationErrorResponse;
import com.nimbusds.oauth2.sdk.client.ClientRegistrationResponse;
import com.nimbusds.oauth2.sdk.http.CommonContentTypes;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.oauth2.sdk.util.JSONObjectUtils;
import com.nimbusds.openid.connect.sdk.AuthenticationErrorResponse;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.AuthenticationResponse;
import com.nimbusds.openid.connect.sdk.AuthenticationResponseParser;
import com.nimbusds.openid.connect.sdk.AuthenticationSuccessResponse;
import com.nimbusds.openid.connect.sdk.ClaimsRequest;
import com.nimbusds.openid.connect.sdk.Nonce;
import com.nimbusds.openid.connect.sdk.OIDCAccessTokenResponse;
import com.nimbusds.openid.connect.sdk.OIDCResponseTypeValue;
import com.nimbusds.openid.connect.sdk.OIDCTokenResponseParser;
import com.nimbusds.openid.connect.sdk.UserInfoErrorResponse;
import com.nimbusds.openid.connect.sdk.UserInfoRequest;
import com.nimbusds.openid.connect.sdk.UserInfoResponse;
import com.nimbusds.openid.connect.sdk.UserInfoSuccessResponse;
import com.nimbusds.openid.connect.sdk.claims.ClaimRequirement;
import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientInformation;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientInformationResponse;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientMetadata;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientRegistrationRequest;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientRegistrationResponseParser;
import com.nimbusds.openid.connect.sdk.util.DefaultJWTDecoder;

import fi.iki.elonen.NanoHTTPD;
import fi.iki.elonen.ServerRunner;

/**
 * Skeleton code for building an RP.
 *
 * Using the nanohttpd library (https://github.com/NanoHttpd/nanohttpd) as the
 * webserver, and Nimbus OAauth
 * (http://connect2id.com/products/nimbus-oauth-openid-connect-sdk) for OpenID
 * Connect support.
 *
 * @author Rebecka Gulliksson, rebecka.gulliksson@umu.se
 *
 */
public class RPServer extends NanoHTTPD {
	/**
	 * Which port (on localhost) the RP listens to for the redirect URI.
	 */
	public static int SERVER_PORT = 8090;

	/**
	 * Logger instance.
	 */
	private static Logger logger = Logger.getLogger(RPServer.class.getName());

	private OIDCProviderMetadata providerMetadata;

	private URI redirectURI;

	private OIDCClientInformation clientInformation;

	private State lastState;

	/**
	 * Constructor for the RP server.
	 *
	 * Loads the client metadata from file.
	 *
	 * @throws IOException
	 * @throws URISyntaxException
	 * @throws ParseException
	 * @throws SerializeException
	 */
	public RPServer() throws IOException, ParseException, URISyntaxException,
			SerializeException {
		super(SERVER_PORT);

		String jsonMetadata = readFromFile("client.json");

		// TODO use the metadata to create a client
		OIDCClientMetadata metadata = OIDCClientMetadata.parse(JSONObjectUtils
				.parseJSONObject(jsonMetadata));
		redirectURI = new URI("http://localhost:8090/code_flow_callback");

		// TODO get the provider configuration information
		providerMetadata = getProviderConfig();

		// TODO register with the provider
		clientInformation = doClientRegistration(metadata);
	}

	private OIDCClientInformation doClientRegistration(
			OIDCClientMetadata metadata) throws ParseException,
			SerializeException, IOException {
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

	private OIDCProviderMetadata getProviderConfig() throws URISyntaxException,
			IOException, ParseException {
		URI issuerURI = new URI("https://dirg.org.umu.se:8092");
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

	/**
	 * Main method to start running the web server.
	 *
	 * @param args
	 */
	public static void main(String[] args) {
		ServerRunner.run(RPServer.class);
	}

	/**
	 * Callback for the web server when receiving a request. Currently has
	 * support for three paths:
	 *
	 * '/': displays the main page
	 *
	 * 'code_flow': starts authentication using the OpenID Connect code flow
	 *
	 * 'auth_callback': where the authentication response from the provider is
	 * received (must match the path specified in the redirect URI in the client
	 * metadata)
	 *
	 * @param session
	 *            the incoming request
	 *
	 * @return the response to the request.
	 */
	@Override
	public Response serve(IHTTPSession session) {
		UserInfoSuccessResponse userInfoClaims;
		if (session.getUri().equals("/")) { // Index page
			return loadPageFromFile("index.html");
		} else if (session.getUri().endsWith("implicit_flow_callback")) {
			return loadPageFromFile("repost_fragment.html");
		} else if (session.getUri().endsWith("authenticate")) {
			// TODO make authentication request
			String url = null;
			try {
				url = doAuthReq();
			} catch (SerializeException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			return redirect(url); // TODO insert the redirect URL
		} else if (session.getUri().endsWith("code_flow_callback")) {
			// Callback redirect URI
			String url = session.getUri() + "?"
					+ session.getQueryParameterString();

			// TODO parse authentication response from url
			AuthenticationSuccessResponse authResp = parseAuthResp(url);

			// TODO make token request
			OIDCAccessTokenResponse accessTokenResp = makeTokenReq(authResp
					.getAuthorizationCode());
			// TODO verify the id token
			JWT idToken = accessTokenResp.getIDToken();

			// TODO make userinfo request
			userInfoClaims = makeUserInfoReq(accessTokenResp.getAccessToken());

			ReadOnlyJWTClaimsSet idTokenClaims = null;
			try {
				idTokenClaims = verifyIdToken(idToken);
			} catch (ParseException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			return successPage(authResp.getAuthorizationCode(),
					accessTokenResp.getAccessToken(),
					idToken.getParsedString(), idTokenClaims, userInfoClaims);
		} else if (session.getUri().endsWith("repost_fragment")) {
			try {
				session.parseBody(new HashMap<String, String>());
				Map<String, String> postParams = session.getParms();
				// Callback redirect URI
				String url = session.getUri() + "#"
						+ postParams.get("url_fragment");
				AuthenticationSuccessResponse authResp = parseAuthResp(url);

				JWT idToken = authResp.getIDToken();
				ReadOnlyJWTClaimsSet idTokenClaims = null;
				try {
					idTokenClaims = verifyIdToken(idToken);
				} catch (ParseException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
				return successPage(authResp.getAuthorizationCode(), null,
						idToken.getParsedString(), idTokenClaims, null);
			} catch (IOException | ResponseException e) {
				// TODO proper error handling
				e.printStackTrace();
			}
		}

		return notFound();
	}

	private UserInfoSuccessResponse makeUserInfoReq(AccessToken accessToken) {
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
		JSONObject json = JSONObjectUtils.parseJSONObject(jsonString);

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

	private OIDCAccessTokenResponse makeTokenReq(AuthorizationCode authCode) {
		TokenRequest tokenReq = new TokenRequest(
				providerMetadata.getTokenEndpointURI(),
				clientInformation.getID(), new AuthorizationCodeGrant(authCode,
						redirectURI));

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
			// TODO error handling
		}

		OIDCAccessTokenResponse accessTokenResponse = (OIDCAccessTokenResponse) tokenResponse;
		accessTokenResponse.getAccessToken();
		accessTokenResponse.getIDToken();
		return accessTokenResponse;
	}

	private AuthenticationSuccessResponse parseAuthResp(String url) {
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
		if (!verifyState(successResponse.getState())) {
			// TODO proper error handling
		}

		AuthorizationCode authCode = successResponse.getAuthorizationCode();
		return successResponse;
	}

	private boolean verifyState(State state) {
		return lastState.equals(state);
	}

	private String doAuthReq() throws SerializeException {
		// Generate random state string for pairing the response to the request
		lastState = new State();
		// Generate nonce
		Nonce nonce = new Nonce();
		// Specify scope
		Scope scope = Scope.parse("openid who_am_i");

		// Compose the request
//		ResponseType rt = new ResponseType(OIDCResponseTypeValue.ID_TOKEN,
//				ResponseType.Value.TOKEN);
		ResponseType rt = new ResponseType(
				ResponseType.Value.CODE);
		AuthenticationRequest.Builder authenticationRequest = new AuthenticationRequest.Builder(
				rt, scope,
				clientInformation.getID(), redirectURI);
		
		ClaimsRequest claims = new ClaimsRequest();
		claims.addUserInfoClaim("given_name", ClaimRequirement.ESSENTIAL);
		claims.addUserInfoClaim("family_name", ClaimRequirement.ESSENTIAL);
		claims.addUserInfoClaim("nickname");
		claims.addIDTokenClaim("email", ClaimRequirement.ESSENTIAL);
		claims.addIDTokenClaim("phone_number");
		
		authenticationRequest.state(lastState).nonce(nonce).endpointURI(providerMetadata.getAuthorizationEndpointURI());
		//authenticationRequest.claims(claims).

		URI authReqURI = authenticationRequest.build().toURI();
		System.out.println(authReqURI);
		return authReqURI.toString();
	}

	/**
	 * Build HTML summary of a successful authentication.
	 *
	 * @param authCode
	 *            authorization code obtained from authentication response
	 * @param tokenResponse
	 *            response to the token request
	 * @param idTokenClaims
	 *            claims from the id token
	 * @param userInfoResponse
	 *            response to the user info request
	 * @return response containing HTML formatted summary.
	 */
	private Response successPage(AuthorizationCode authCode,
			AccessToken accessToken, String idToken,
			ReadOnlyJWTClaimsSet idTokenClaims,
			UserInfoSuccessResponse userInfoResponse) {

		try {
			StringBuilder idTokenString = new StringBuilder();
			idTokenString.append(idTokenClaims.toJSONObject().toJSONString());
			idTokenString.append("\n");
			idTokenString.append(idToken);

			StringBuilder userInfoString = new StringBuilder();
			if (userInfoResponse != null) {
				userInfoString.append(userInfoResponse.getUserInfo()
						.toJSONObject().toJSONString());
				if (userInfoResponse.getContentType().equals(
						CommonContentTypes.APPLICATION_JWT)) {
					userInfoString.append("\n");
					userInfoString.append(userInfoResponse.getUserInfoJWT()
							.getParsedString());
				}
			}
			String successPage = readFromFile("success_page.html");
			return new Response(MessageFormat.format(successPage, authCode,
					accessToken, idTokenString, userInfoString));
		} catch (IOException e) {
			logger.severe("Could not read success page from file: " + e);
			return new Response(Response.Status.NOT_FOUND, MIME_PLAINTEXT,
					"Page not found.");
		}
	}

	/**
	 * Read all data from a file.
	 *
	 * @param path
	 *            path of the file
	 * @return All data from the file.
	 * @throws IOException
	 */
	private String readFromFile(String path) throws IOException {
		return new String(Files.readAllBytes(Paths.get(path)),
				StandardCharsets.UTF_8);
	}

	/**
	 * Load a page from file.
	 *
	 * @return response containing the formatted HTML page.
	 */
	private Response loadPageFromFile(String file) {
		try {
			String index = readFromFile(file);
			return new Response(index);
		} catch (IOException e) {
			logger.severe("Could not read index page from file: " + e);
			return new Response(Response.Status.NOT_FOUND, MIME_PLAINTEXT,
					"Page not found.");
		}
	}

	/**
	 * Build 404 Not Found response.
	 *
	 * @return response with HTTP status code 404.
	 */
	private Response notFound() {
		return new Response(Response.Status.NOT_FOUND, MIME_PLAINTEXT,
				"Page not found.");
	}

	/**
	 * Build 301 Redirect response.
	 *
	 * @param redirectURL
	 *            url to redirect to
	 * @return response with HTTP status 301 Redirect.
	 */
	private Response redirect(String redirectURL) {
		Response response = new Response(Response.Status.REDIRECT,
				MIME_PLAINTEXT, "");
		response.addHeader("Location", redirectURL);

		return response;
	}
}
