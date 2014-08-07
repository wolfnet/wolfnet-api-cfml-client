/**
 * This component is a standalone CFML interface for the WolfNet API. This component should not rely
 * on any other code that is part of the WolfNet common repository.
 *
 * @type {com.wolfnet.api.Client}
 */
component accessors="true"
{


	/* PROPERTIES ******************************************************************************* */

	/**
	 * The hostname for the API server.
	 * @type {string}
	 */
	property name="host" type="string";

	/**
	 * The version of the API to make requests of.
	 * @type {string}
	 */
	property name="version" type="string";


	/* CONSTRUCTOR ****************************************************************************** */

	/**
	 * This method is used to initialize the component.
	 * @param  {string} host       The host name for the API server.
	 * @param  {string} version    The version of the API to make requests of.
	 * @return {Client}            A reference to the object being initialized.
	 */
	public Client function init(string host="api.wolfnet.com", string version="1")
	{
		setHost(arguments.host);
		setVersion(arguments.version);

		variables.appScopeKey = "WolfNetApiTokens";

		return this;

	}


	/* PUBLIC METHODS *************************************************************************** */

	/**
	 * This method is the public interface for making requests of the API.
	 * @param  {string} key           The client's API key.
	 * @param  {string} resource      The URI endpoint being requested from the API.
	 * @param  {string} method="GET"  The HTTP method the request should be submitted as.
	 * @param  {struct} data={}       Any query string or body data to be include with the request.
	 * @param  {struct} headers={}    Any header data to be included with the request.
	 * @return {struct}               A struct representation of the data that was returned successfully.
	 */
	public struct function sendRequest(
		required string key,
		required string resource,
		string method="GET",
		struct data={},
		struct headers={}
	) {
		return rawRequest(argumentCollection=arguments);
	}


	/* PRIVATE METHODS ************************************************************************** */

	/**
	 * This method is the private interface for making requests of the API. Notice that it includes
	 * some extra parameters which are used by the client internally to automatically perform API
	 * authentication tasks.
	 * @param  {string}  key             The client's API key.
	 * @param  {string}  resource        The URI endpoint being requested from the API.
	 * @param  {string}  method="GET"    The HTTP method the request should be submitted as.
	 * @param  {struct}  data={}         Any query string or body data to be include with the request.
	 * @param  {struct}  headers={}      Any header data to be included with the request.
	 * @param  {boolean} skipAuth=false  Should this request skip authentication with the API? This
	 *                                   parameter is used as part of the automatic authentication
	 *                                   process. The same function is used to perform authentication
	 *                                   but should not be authenticated itself.
	 * @param  {boolean} reAuth=false    Is this current function call an attempt to re-authenticate
	 *                                   after an initial failed attempt to retrieve data from the API.
	 *                                   This attempt will only be made once before throwing an exception.
	 * @return {struct}                  A struct representation of the data that was returned successfully.
	 */
	private struct function rawRequest(
		required string key,
		required string resource,
		string method="GET",
		struct data={},
		struct headers={},
		boolean skipAuth=false,
		boolean reAuth=false
	) {
		arguments.method = uCase(arguments.method);

		// Make sure the resource is valid.
		if (!isValidResource(arguments.resource)) {
			throw(type="wolfnet.api.client.InvalidResource",
				message="Invalid resource provided for API request.",
				extendedInfo=serializeJSON(arguments));
		}

		// Make sure the method is valid.
		if (!isValidMethod(arguments.method)) {
			throw(type="wolfnet.api.client.InvalidMethod",
				message="Invalid method provided for API request.",
				extendedInfo=serializeJSON(arguments));
		}

		// Make sure the data is valid.
		if (!isValidData(arguments.data)) {
			throw(type="wolfnet.api.client.InvalidData",
				message="Invalid data provided for API request.",
				extendedInfo=serializeJSON(arguments));
		}

		// Retrieve a fully qualified URL for the request based on the requested resource.
		var fullUrl = buildFullUrl(arguments.resource);

		// Unless told otherwise, attempt to retrieve an API token.
		if (!arguments.skipAuth) {
			arguments.headers.api_token = getApiToken(arguments.key, arguments.reAuth);
		}

		// Start building an HTTP object for making the request.
		var httpObj = new http();
		httpObj.setUrl(fullUrl);
		httpObj.setMethod(arguments.method);
		httpObj.addParam(type="header", name="Accept", value="application/json");

		// Depending on the method we will pass data in the request differently.
		switch (arguments.method) {

			case "GET":
				for (var key in arguments.data) {
					httpObj.addParam(type="url", name=key, value=arguments.data[key]);
				}
				break;

			case "PUT":
				httpObj.addParam(type="header", name="Content-Type", value="application/json");
				httpObj.addParam(type="body", value=serializeJSON(arguments.data));
				break;

			case "POST":
				for (var key in arguments.data) {
					httpObj.addParam(type="formField", name=key, value=arguments.data[key]);
				}
				break;

		}

		// Append any header data to the HTTP object.
		for (var key in arguments.headers) {
			httpObj.addParam(type="header", name=key, value=arguments.headers[key]);
		}

		// Perform the actual HTTP request.
		var httpResponse = httpObj.send();
		var httpPrefix = httpResponse.getPrefix();

		if (!structKeyExists(httpPrefix, 'status_code')) {
			throw(type="wolfnet.api.client.ConnectionFailure",
				message="Unable to connected to the API server.",
				detail=serializeJSON(httpPrefix));
		}

		// Build a structure representation of the HTTP response from the API.
		var apiResponse = {
			requestUrl = fullUrl,
			requestMethod = arguments.method,
			requestData = arguments.data,
			responseStatusCode = httpPrefix.status_code,
			responseData = httpPrefix.filecontent,
			timestamp = now(),
		};

		// If the response type is JSON attempt to deserialize the response body.
		if (httpPrefix.mimetype == "application/json") {

			try {
				apiResponse.responseData = deserializeJSON(httpPrefix.filecontent);
			}
			catch (Any exception) {
				throw(type="wolfnet.api.client.InvalidJsonResponse",
					message="An error occurred while attempting to deserialize the JSON API response.",
					extendedInfo=serializeJSON(apiResponse)
					);
			}

		}

		// The API returned a 401 Unauthorized so throw an exception.
		if (apiResponse.responseStatusCode == 401) {
			throw(type="wolfnet.api.client.Unauthorized",
				message=httpPrefix.status_text,
				extendedInfo=serializeJSON(apiResponse));

		// The API returned a 403 Forbidden so throw an exception
		} else if (apiResponse.responseStatusCode == 403) {
			throw(type="wolfnet.api.client.Forbidden",
				message=httpPrefix.status_text,
				extendedInfo=serializeJSON(apiResponse));

		// The API returned a 400 Bad Response because the token it was given was not valid, so attempt to re-authenticated and perform the request again.
		} else if (apiResponse.responseStatusCode == 400
			&& (
				(structKeyExists(apiResponse.responseData.metadata.status, "errorCode") && apiResponse.responseData.metadata.status.errorCode == "Auth1005")
				|| (structKeyExists(apiResponse.responseData.metadata.status, "statusCode") && apiResponse.responseData.metadata.status.statusCode == "Auth1005")
			)
			&& !arguments.reAuth) {
			return rawRequest(argumentCollection=arguments, reAuth=true);

		// We received an unexpected response from the API so throw an exception.
		} else if (apiResponse.responseStatusCode != 200) {
			throw(type="wolfnet.api.client.BadResponse",
				message=httpPrefix.status_text,
				extendedInfo=serializeJSON(apiResponse));

		}

		// If we made it this far return the API response data.
		return apiResponse;

	}


	/**
	 * This method uses the host value included during initialization and a resource string to create
	 * a fully qualified API URL.
	 * @param  {string}  resource  The URI endpoint being requested from the API.
	 * @return {string}            A fully qualified API URL.
	 */
	private string function buildFullUrl(required string resource)
	{
		// TODO: The environment configuration needs to be updated to be only a host name and not include protocol.
		// return "https://" & variables.apiHostName & arguments.resource;
		return getHost() & arguments.resource;

	}


	/**
	 * This method validates that a provided resource string is formatted correctly.
	 * @param  {string}  resource  The URI endpoint being requested from the API.
	 * @return {Boolean}           Is the resource valid? true/false
	 */
	private boolean function isValidResource(required string resource)
	{
		// TODO: Add more validation criteria.

		// If the resource does not start with a leading slash it is not valid.
		if (left(arguments.resource, 1) != "/") {
			return false;
		} else {
			return true;
		}

	}


	/**
	 * This method validates that a given method string matches one that is supported by the API.
	 * @param  {string}  method  The HTTP method the request should be submitted as.
	 * @return {Boolean}         Is the method valid? true/false
	 */
	private boolean function isValidMethod(required string method)
	{
		if (listFindNoCase("GET,POST,PUT,DELETE", arguments.method) == 0) {
			return false;
		} else {
			return true;
		}

	}


	/**
	 * This method validates that the given data can be used with the API request.
	 * @param  {struct}  data  Any query string or body data to be include with the request.
	 * @return {Boolean}       Is the data valid? true/false
	 */
	private boolean function isValidData(required struct data)
	{
		var valid = true;

		// Ensure that only simple values are included in the data. ie. strings, numbers, and booleans.
		for (var key in arguments.data) {
			if (!isSimpleValue(arguments.data[key])) {
				valid = false;
				break;
			}
		}

		return valid;

	}


	/**
	 * This method attempts to retrieve a token for use with an API request as authentication. If
	 * possible it will retrieve the token from a persistent cache to minimize the number of API
	 * requests that are made.
	 * @param  {[type]} required string        key           [description]
	 * @param  {[type]} boolean  force=false   [description]
	 * @return {[type]}          [description]
	 */
	private any function getApiToken(required string key, boolean force=false)
	{
		// Unless forced to do otherwise, attempt to retrieve the token from a cache.
		var token = arguments.force ? "" : retrieveApiTokenDataFromCache(arguments.key);

		// If a token was not retrieved from the cache perform an API request to retrieve a new one.
		if (token == "") {
			var data = {
				key = arguments.key,
				v = getVersion(),
			};

			var authResponse = rawRequest(argumentCollection={
				key = arguments.key,
				resource = '/core/auth',
				method = "POST",
				data = data,
				skipAuth = true, // Since we don't have a valid token we don't want to attempt to include it.
				});

			// TODO: Validate that the response includes the data we need.

			token = updateApiTokenDataCache(arguments.key, authResponse.responseData.data).api_token;

		}

		return token;

	}


	/**
	 * This method retrieves a token from the application scope or an empty string if the token is
	 * expired or none can be found.
	 * @param  {string}  key  The client's API key.
	 * @return {string}       [description]
	 */
	private string function retrieveApiTokenDataFromCache(required string key)
	{
		ensureTokenCacheExists();

		var keyExists = structKeyExists(application[variables.appScopeKey].token, arguments.key);
		var tokenData = keyExists ? application[variables.appScopeKey].token[arguments.key] : {};
		var validData = structKeyExists(tokenData, "api_token") && structKeyExists(tokenData, "expiration");

		// TODO: check if the token has or is about to become expired.

		if (validData) {
			var token = application[variables.appScopeKey].token[arguments.key].api_token;
		} else {
			return "";
		}

		return token;

	}


	/**
	 * This method stores API authentication token data in a request persistent cache.
	 * @param  {string}  key        The client's API key.
	 * @param  {struct}  tokenData  Token data to be cached.
	 * @return {struct}             Return the same token data for function chaining.
	 */
	private struct function updateApiTokenDataCache(required string key, required struct tokenData)
	{
		ensureTokenCacheExists();
		application[variables.appScopeKey].token[arguments.key] = arguments.tokenData;

		return arguments.tokenData;

	}


	/**
	 * This method ensures that the necessary structures are available to perform token data caching.
	 * @return {void}
	 */
	private void function ensureTokenCacheExists()
	{

		if (!structKeyExists(application, variables.appScopeKey)) {
			application[variables.appScopeKey] = {};
		}

		if (!structKeyExists(application[variables.appScopeKey], "token")) {
			application[variables.appScopeKey].token = {};
		}

	}


}
