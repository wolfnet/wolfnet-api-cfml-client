/**
 * Client interface for the WolfNet API.
 *
 * This class is a ColdFusion implementation of the WolfNet API Client. It is used to
 * make requests to the API and receive responses from the API. The scope of this class should not
 * extend beyond basic HTTP communication. Any other logic such as caching should be accomplished
 * by decorating or advising this class.
 *
 * In order for the API client to perform requests to the API it must first prove to the API that it
 * has valid credentials to do so, namely a valid and active *API key*. With the API key the client
 * can retrieve an API token (see API documentation) which is then used to make any subsequent
 * requests.
 */
component
{


	/* PROPERTIES ******************************************************************************* */

	/**
	 * The hostname for the API where requests will be sent.
	 * @type string
	 */
	property name="host";

	/**
	 * The API version that will be interacted with.
	 * @type numeric
	 */
	property name="version";

	property name="logger";


	/* CONSTRUCTOR ****************************************************************************** */

	/**
	 * Constructor Method
	 *
	 * This constructor method instantiates the ApiClient class and allows the consumer to specify
	 * details about what API should be interacted with.
	 *
	 * @param string  host    The hostname for the API where requests will be sent.
	 * @param integer version The API version that will be interacted with.
	 *
	 * @return Client
	 *
	 */
	public Client function init(
		string host="api.wolfnet.com",
		numeric version=1
	) {

		variables.host = arguments.host;
		variables.version = arguments.version;

		variables.timeout = 500; // HTTP Timeout in milliseconds

		return this;

	}


	/* PUBLIC METHODS *************************************************************************** */

	/**
	 * This method is used to authenticate with the API and retrieve an API token which is needed
	 * to perform any other requests to the API.
	 *
	 * @param  string  key      API key to be used for authentication.
	 * @param  struct  headers  The HTTP headers to be sent with the request.
	 * @param  struct  options  Extra options that may be passed into the request. This parameter
	 *                          mostly exists to facilitate the decorators.
	 *
	 * @return struct           The API response structure.
	 *
	 */
	public struct function authenticate(
		required string key,
		struct headers={},
		struct options={}
	) {
		var data = {
			'key' = arguments.key,
			'v' = variables.version,
		};

		return performRequest(
			'/core/auth',
			'POST',
			data,
			arguments.headers ?: {}
			);

	}


	/**
	 * This method makes pre-authenticated requests to the WolfNet API and returns the response.
	 *
	 * @param  string  token     The API token that should be used to the API requests.
	 * @param  string  resource  The API endpoint the request should be made to.
	 * @param  string  method    The HTTP verb that should be used to make the request.
	 * @param  struct  data      Any data that should be passed along with the request.
	 * @param  struct  headers   The HTTP headers to be sent with the request.
	 * @param  struct  options   Extra options that may be passed into the request. This parameter
	 *                           mostly exists to facilitate the decorators.
	 *
	 * @return struct            An array containing the HTTP response.
	 *
	 */
	public struct function sendRequest(
		required string token,
		required string resource,
		required string method = "GET",
		struct data = {},
		struct headers = {},
		struct options = {}
	) {

		arguments.headers['api_token'] = arguments.token;

		return performRequest(
			arguments.resource,
			arguments.method,
			arguments.data,
			arguments.headers
			);

	}


	/* PRIVATE METHODS ************************************************************************** */

	/**
	 * This method takes in request parameters and performs HTTP requests to the WolfNet API.
	 *
	 * @param  string  resource  The API endpoint the request should be made to.
	 * @param  string  method    The HTTP verb that should be used to make the request.
	 * @param  array   data      Any data that should be passed along with the request.
	 * @param  array   headers   The HTTP headers to be sent with the request.
	 *
	 * @throws  wolfnet.api.client   This exception is thrown any time there is an issue
	 *                               with the request. This exception should then be caught
	 *                               later and displayed as a user friendly message.
	 *
	 * @return  struct  An array containing the HTTP response.
	 */
	private struct function performRequest(
		required string resource,
		required string method = "GET",
		struct data = {},
		struct headers = {}
	) {

		this.log('info', 'Starting API request.', arguments);

		// Make sure the method is valid.
		if (!isValidMethod(arguments.method)) {
			throw(type="wolfnet.api.client.InvalidMethod",
				message="Invalid method provided for API request.",
				extendedInfo=serializeJSON(arguments)
				);
		}

		try {

			var uri = uriFromResource(arguments.resource);

			validateRequestData(arguments.data);

		}
		catch (wolfnet.api.client exception) {
			throw(type=exception.type,
				message=exception.message & ' While attempting request to (' & uri & ').',
				detail=exception.detail,
				extendedInfo=serializeJSON(arguments)
				);
		}

		// TODO: Implement CF HTTP request.

		var httpObj = new http();
		httpObj.setTimeOut(variables.timeout);
		httpObj.setUrl(uri);
		httpObj.setMethod(arguments.method);

		// For now the client will only accept JSON responses.
		arguments.headers['Accept'] = 'application/json';
		// Adding HTTP Encoding header.
		arguments.headers['Accept-Encoding'] = 'gzip, deflate';

		// Apply data to the requests
		// Depending on the method we will pass data in the request differently.
		switch (arguments.method) {

			case "GET":
				for (var dataKey in arguments.data) {
					httpObj.addParam(type="url", name=dataKey, value=arguments.data[dataKey]);
				}
				break;

			case "POST":
				for (var dataKey in arguments.data) {
					httpObj.addParam(type="formField", name=dataKey, value=arguments.data[dataKey]);
				}
				break;

			case "PUT":
				httpObj.addParam(type="header", name="Content-Type", value="application/json");
				httpObj.addParam(type="body", value=serializeJSON(arguments.data));
				break;

		}

		// Append any header data to the HTTP object.
		for (var headerKey in arguments.headers) {
			httpObj.addParam(type="header", name=headerKey, value=arguments.headers[headerKey]);
		}

		// Perform the actual HTTP request.
		var httpResponse = httpObj.send();
		var httpPrefix = httpResponse.getPrefix();

		try {
			validateResponse(httpPrefix);
		}
		catch (wolfnet.api.client exception) {
			throw(type=exception.type,
				message=exception.message & ' While attempting request to (' & uri & ').',
				detail=exception.detail,
				extendedInfo=serializeJson(parseResponse(httpPrefix, uri, arguments.method, arguments.data)));
		}

		return parseResponse(httpPrefix, uri, arguments.method, arguments.data);

	}


	/**
	 * This method validates the data to be sent with the HTTP request.
	 *
	 * Specifically we are checking to make sure that the data which is being sent to the API can be
	 * easily converted into a format which works with basic HTTP requests. This means we only want
	 * Scalar values such as numbers, strings, and booleans.
	 *
	 * @param  array  data  The data to be validated.
	 *
	 * @throws Wolfnet_Api_ApiException  This exception is thrown if any of the data that was
	 *                                   given does not meet the validation criteria.
	 *
	 * @return null
	 */
	private void function validateRequestData(required struct data)
	{

		// Loop over each key in the data and check if they are scalar (simple) values.
		for (var dataKey in arguments.data) {

			if (!isSimpleValue(arguments.data[dataKey])) {
				throw(type='wolfnet.api.client.InvalidData',
					message='Tried to send invalid data to the API.',
					detail='[' & dataKey & '] is not a valid API argument. '
					      & 'All API arguments must be scalar values. ');
			}

		}

	}


	/**
	 * This method turns a resource string into a fully qualified URL using the API host and port
	 * that were passed into the constructor of API Client class.
	 *
	 * @param  string  resource  The API resource (endpoint) be be converted to a URL.
	 *
	 * @return string            A fully qualified URL to the API.
	 *
	 */
	private string function uriFromResource(required string resource)
	{
		// TODO: Add more validation criteria.

		// If the resource does not start with a leading slash it is not valid.
		if (left(arguments.resource, 1) != "/") {
			throw(type="wolfnet.api.client.InvalidResource",
				message="Invalid resource provided for API request.");
		}

		return variables.host & arguments.resource;

	}


	/**
	 * This method validates that a given method string matches one that is supported by the API.
	 *
	 * @param  {string}  method  The HTTP method the request should be submitted as.
	 *
	 * @return {Boolean}         Is the method valid? true/false
	 *
	 */
	private boolean function isValidMethod(required string method)
	{
		if (listFindNoCase('GET,POST,PUT,DELETE', arguments.method) == 0) {
			return false;
		} else {
			return true;
		}

	}


	/**
	 * This method validates the HTTP response from the API. If the response does not pass validation
	 * an exception is thrown which can be caught and acted upon later.
	 *
	 * @param  mixed  response  A response from the CF HTTP Request
	 *
	 * @return null
	 *
	 */
	private function validateResponse(required struct response)
	{

		if (!structKeyExists(arguments.response, 'status_code')) {
			throw(type="wolfnet.api.client.ConnectionFailure",
				message="Unable to connect to the API server.",
				extendedInfo=serializeJSON(arguments.response));
		}

		var responseCode = arguments.response.status_code;

		/**
		 * This response code we received is not code 200. We don't know how to deal with this
		 * response at this time so we will need to throw an exception.
		 *
		 * NOTE: At some point in the future we will probably need to make the client capable of
		 * dealing with responses such as redirects.
		 *
		 */
		if (responseCode != 200) {

			var responseText = arguments.response.status_text ?: '';
			var responseBody = arguments.response.filecontent ?: '{}';

			try {
				var responseData = deserializeJson(responseBody);
			} catch (Any exception) {
				throw(type="wolfnet.api.client.InvalidJsonResponse",
					message="An error occurred while attempting to deserialize the JSON API response.",
					extendedInfo=serializeJSON([formattedResponse, arguments.response])
					);
			}

			var metadata = responseData.metadata ?: {};
			var status = metadata.status ?: {};
			var errorCode = status.errorCode ?: '';
			var statusCode = status.statusCode ?: '';
			var errorID = status.error_id ?: '';
			var extendedInfo = status.extendedInfo ?: '';

			// TODO: These two variables are used repeatedly below. Could be done better.
			var errorIDMessage = (errorID != '') ? 'API Error ID: ' & errorID : '';
			var errorMessage = (extendedInfo != '') ? 'The API says: [' & extendedInfo & ']' : '';

			// Here we will handle special API error responses.

			/**
			 * The API has indicated that the request was made without a valid API token so we will
			 * throw a special exception that we can can catch and attempt to re-authenticate.
			 */
			var authErrorCode = 'Auth1005';
			if (errorCode == authErrorCode || statusCode == authErrorCode) {
				throw(type='wolfnet.api.client.Unauthorized.API',
					message='Remote request was not authorized.',
					detail='The WolfNet API has responded that it did not receive a valid API token.'
					      & errorIDMessage & ' ' & errorMessage
					);
			}

			/**
			 * The API has indicated that the request was made but the data can only be accessed by
			 * a user who has authenticated (double opt-in) their account.
			 */
			var userAuthErrorCode = 'Auth1004';
			if (errorCode == userAuthErrorCode || statusCode == userAuthErrorCode) {
				throw(type='wolfnet.api.client.Unauthorized.User',
					message='User must be authenticated to view this information.',
					detail='The WolfNet API has responded the data requested can only be viewed by '
					      & 'a user that has authenticated their account. '
					      & errorIDMessage & ' ' & errorMessage
					);
			}

			// The API returned a 401 Unauthorized
			if (responseCode == 401) {
				throw(type='wolfnet.api.client.Unauthorized',
					message='Remote request resulted in a [401 Unauthorized] response.',
					detail='The WolfNet API has indicated that the request was made '
					      & 'without properly authentication. '
					      & errorIDMessage & ' ' & errorMessage
					);
			}

			// The API returned a 500 Internal Server Error
			if (responseCode == 500) {
				throw(type='wolfnet.api.client.InteralServerError',
					message='Remote request resulted in a [500 Internal Server Error] response.',
					detail='The WolfNet API appears to be unresponsive at this time.'
					      & errorIDMessage & ' ' & errorMessage
					);
			}

			// The API returned a 503 Service Unavailable
			if (responseCode == 503) {
				throw(type='wolfnet.api.client.ServerUnavailable',
					message='Remote request resulted in a [503 Service Unavailable] response.',
					detail='The WolfNet API appears to be unresponsive at this time but should be back soon.'
					      & errorIDMessage & ' ' & errorMessage
					);
			}

			// The API returned a 403 Forbidden
			if (responseCode == 403) {
				throw(type='wolfnet.api.client.Forbidden',
					message='Remote request resulted in a [403 Forbidden] response.',
					detail='An attempt was made to request data that is not available to the key that '
					      & 'was used to authenticate the request.'
					      & errorIDMessage & ' ' & errorMessage
					);
			}

			// The API returned a 400 Bad Response
			// There are several reasons why this might have happened so we should check for those
			if (responseCode == 400) {
				throw(type='wolfnet.api.client.BadResponse',
					message='Remote request was not successful.',
					detail='The WolfNet API has indicated that the request was "bad" for an unknown reason.'
					      & errorIDMessage & ' ' & errorMessage
					);
			}

			// There was some other issue that we have not anticipated.
			throw(type='wolfnet.api.client.UnknownResponse',
				message='Remote request was not successful.',
				details='The WolfNet plugin received an API response it is not prepared to deal with. '
				       & 'Status: #responseCode# #responseText#; '
				       & errorIDMessage & ' ' & errorMessage
				);

		}

	}


	/**
	 * This method is used to abstract a raw CF HTTP response from the API into a format that
	 * we control, in this case an array. This way if the WP response changes we only have one place
	 * in our code to change.
	 *
	 * Our structure currently contains for request and response data to make debugging easier.
	 *
	 * NOTE: This method expects that the response is an array at this point. If the response is not
	 * and array it should have been caught by the validation method (validateResponse) and then
	 * resulted in an exception.
	 *
	 * @param  array   response     The CF HTTP API response.
	 * @param  string  uri          The request URI.
	 * @param  string  method       The request HTTP verb.
	 * @param  array   requestData  The request data.
	 *
	 * @return array                A uniform array of request and response data.
	 *
	 */
	private function parseResponse(
		required struct response,
		required string uri,
		required string method,
		required struct requestData
	) {

		var formattedResponse = {
			'requestUrl' = arguments.uri,
			'requestMethod' = arguments.method,
			'requestData' = arguments.requestData,
			'responseStatusCode' = arguments.response.status_code,
			'responseData' = arguments.response.filecontent,
			'timestamp' = Now(),
			'fromCache' = false,
		};

		if (arguments.response.mimetype == 'application/json') {

			try {
				formattedResponse['responseData'] = deserializeJson(formattedResponse['responseData']);
			}
			catch (Any exception) {
				throw(type="wolfnet.api.client.InvalidJsonResponse",
					message="An error occurred while attempting to deserialize the JSON API response.",
					extendedInfo=serializeJSON([formattedResponse, arguments.response])
					);
			}

		}

		return formattedResponse;

	}


	private void function log(required string type, required string message, any data)
	{
		var logger = variables.logger ?: {};

		if (structCount(logger) > 0 && structKeyExists(logger, arguments.type)) {
			logger[arguments.type](arguments.message, arguments.data ?: '');
		}

	}


}
