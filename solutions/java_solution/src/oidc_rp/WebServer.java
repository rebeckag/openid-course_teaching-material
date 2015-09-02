package oidc_rp;

import static spark.Spark.exception;
import static spark.Spark.get;
import static spark.Spark.post;
import static spark.SparkBase.port;

import java.io.IOException;
import java.net.URISyntaxException;
import java.text.MessageFormat;
import java.util.logging.Logger;

import utils.FileHandling;

import com.nimbusds.jwt.ReadOnlyJWTClaimsSet;
import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.SerializeException;
import com.nimbusds.oauth2.sdk.http.CommonContentTypes;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.openid.connect.sdk.UserInfoSuccessResponse;

/**
 * Skeleton code for building an OpenID Connect Public Client.
 *
 * Using the nanohttpd library (https://github.com/NanoHttpd/nanohttpd) as the
 * webserver, and Nimbus OAauth
 * (http://connect2id.com/products/nimbus-oauth-openid-connect-sdk) for OpenID
 * Connect support.
 *
 * @author Rebecka Gulliksson, rebecka.gulliksson@umu.se
 *
 */
public class WebServer {
	/**
	 * Which port (on localhost) the RP listens to for the redirect URI.
	 */
	public static int SERVER_PORT = 8090;

	/**
	 * Issuer identifier (URL of the provider)
	 */

	public static String ISSUER = "https://dirg.org.umu.se:8092";

	/**
	 * Logger instance.
	 */
	private static Logger logger = Logger.getLogger(WebServer.class.getName());

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
	public static void main(String[] args) throws ParseException, IOException,
			URISyntaxException, SerializeException {
		String jsonMetadata = FileHandling.readFromFile("client.json");
		Client client = new Client(jsonMetadata, ISSUER);

		/*** Spark webserver setup ***/
		port(SERVER_PORT);

		/*** Spark webserver routes ***/

		/* displays the main page */
		get("/", (req, res) -> loadPageFromFile("index.html"));

		/*
		 * where the authentication response from the provider is received when
		 * using implicit or hybrid flow
		 */
		get("/implicit_flow_callback",
				(req, res) -> loadPageFromFile("repost_fragment.html"));

		/*
		 * starts authentication using the OpenID Connect code flow
		 */
		get("/authenticate", client::authenticate);

		/*
		 * where the authentication response from the provider is received when
		 * using code flow
		 */
		get("/code_flow_callback", client::codeFlowCallback);

		/*
		 * where the fragment identifier is received after being parsed by the
		 * client (using Javascript)
		 */
		post("/repost_fragment", client::repostFragment);

		/* default handling if a file a requested file can not be found */
		exception(IOException.class, (e, request, response) -> {
			response.status(404);
			response.body("Resource not found: " + e);
		});
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
	public static String successPage(AuthorizationCode authCode,
			AccessToken accessToken, String idToken,
			ReadOnlyJWTClaimsSet idTokenClaims,
			UserInfoSuccessResponse userInfoResponse) throws IOException {

		StringBuilder idTokenString = new StringBuilder();
		idTokenString.append(idTokenClaims.toJSONObject().toJSONString());
		idTokenString.append("\n");
		idTokenString.append(idToken);

		StringBuilder userInfoString = new StringBuilder();
		if (userInfoResponse != null) {
			userInfoString.append(userInfoResponse.getUserInfo().toJSONObject()
					.toJSONString());
			if (userInfoResponse.getContentType().equals(
					CommonContentTypes.APPLICATION_JWT)) {
				userInfoString.append("\n");
				userInfoString.append(userInfoResponse.getUserInfoJWT()
						.getParsedString());
			}
		}
		String successPage = FileHandling.readFromFile("success_page.html");
		return MessageFormat.format(successPage, authCode, accessToken,
				idTokenString, userInfoString);
	}

	/**
	 * Load a page from file.
	 *
	 * @return response containing the formatted HTML page.
	 * @throws IOException
	 */
	private static String loadPageFromFile(String file) throws IOException {
		return FileHandling.readFromFile(file);
	}

}
