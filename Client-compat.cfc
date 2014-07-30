<!---
 This component is a standalone CFML interface for the WolfNet API. This component should not rely
 on any other code that is part of the WolfNet common repository.

 ******************
 BACKWARDS COMPATIBILITY VERSION:
 This version of the component is intended for use when CF8 backwards compatibility is required.
 ******************
--->
<cfcomponent output="false" accessors="true">

	<cfproperty name="host" type="string" />
	<cfproperty name="version" type="string" />


	<!--- CONSTRUCTOR ****************************************************************************** */

	 This method is used to initialize the component.
	 @param  {string} host       The host name for the API server.
	 @param  {string} version    The version of the API to make requests of.
	 @return {Client}            A reference to the object being initialized.
	 --->

	<cffunction name="init" output="false" access="public" returntype="Client-compat">
		<cfargument name="host" type="string" required="false" default="api.wolfnet.com" />
		<cfargument name="version" type="string" required="false" default="1" />

		<cfset setHost(arguments.host) />
		<cfset setVersion(arguments.version) />
		<cfset variables.appScopeKey = "WolfNetApiTokens" />

		<cfreturn this>

	</cffunction>


	<!--- PUBLIC METHODS *************************************************************************** --->

	<!---
	This method is the public interface for making requests of the API.
	 @param  {string} key           The client's API key.
	 @param  {string} resource      The URI endpoint being requested from the API.
	 @param  {string} method="GET"  The HTTP method the request should be submitted as.
	 @param  {struct} data={}       Any query string or body data to be include with the request.
	 @param  {struct} headers={}    Any header data to be included with the request.
	 @return {struct}               A struct representation of the data that was returned successfully.
	--->
	<cffunction name="sendRequest" access="public" returntype="struct" output="false">
		<cfargument name="key" type="string" required="true" />
		<cfargument name="resource" type="string" required="true" />
		<cfargument name="method" type="string" required="false" default="GET" />
		<cfargument name="data" type="struct" required="false" default="#structNew()#" />
		<cfargument name="headers" type="struct" required="false" default="#structNew()#" />

		<cfreturn  rawRequest(argumentCollection=arguments) />

	</cffunction>



	<!--- PRIVATE METHODS *************************************************************************** --->

	<!---
	 This method is the private interface for making requests of the API. Notice that it includes
	 some extra parameters which are used by the client internally to automatically perform API
	 authentication tasks.
	 @param  {string}  key             The client's API key.
	 @param  {string}  resource        The URI endpoint being requested from the API.
	 @param  {string}  method="GET"    The HTTP method the request should be submitted as.
	 @param  {struct}  data={}         Any query string or body data to be include with the request.
	 @param  {struct}  headers={}      Any header data to be included with the request.
	 @param  {boolean} skipAuth=false  Should this request skip authentication with the API? This
	                                   parameter is used as part of the automatic authentication
	                                   process. The same function is used to perform authentication
	                                   but should not be authenticated itself.
	 @param  {boolean} reAuth=false    Is this current function call an attempt to re-authenticate
	                                   after an initial failed attempt to retrieve data from the API.
	                                   This attempt will only be made once before throwing an exception.
	 @return {struct}                  A struct representation of the data that was returned successfully.
	--->
	<cffunction name="rawRequest" access="private" returntype="struct" output="false">
		<cfargument name="key" type="string" required="true" />
		<cfargument name="resource" type="string" required="true" />
		<cfargument name="method" type="string" required="false" default="GET" />
		<cfargument name="data" type="struct" required="false" default="#structNew()#" />
		<cfargument name="headers" type="struct" required="false" default="#structNew()#" />
		<cfargument name="skipAuth" type="boolean" required="true" default = false />
		<cfargument name="reAuth" type="boolean" required="true" default = false />

		<cfset var fullUrl = "" />
		<cfset var itemkey = "" />
		<cfset var httpPrefix = "" />
		<cfset var apiResponse = "" />


		<cfset arguments.method = uCase(arguments.method) />

		<!--- Make sure the resource is valid. --->
		<cfif !isValidResource(arguments.resource)>
			<cfthrow type="wolfnet.api.client.InvalidResource"
					 		  message="Invalid resource provided for API request."
					 		  extendedInfo="#serializeJSON(arguments)#" />
		</cfif>

		<!--- Make sure the method is valid. --->
		<cfif !isValidMethod(arguments.method)>
			<cfthrow type="wolfnet.api.client.InvalidResource"
					 		  message="Invalid method provided for API request."
					 		  extendedInfo="#serializeJSON(arguments)#" />
		</cfif>

		<!--- Make sure the data is valid. --->
		<cfif !isValidData(arguments.data)>
			<cfthrow type="wolfnet.api.client.InvalidData"
					 		  message="Invalid data provided for API request."
					 		  extendedInfo="#serializeJSON(arguments)#" />
		</cfif>


		<cfscript>

			// Retrieve a fully qualified URL for the request based on the requested resource.
			fullUrl = buildFullUrl(arguments.resource);

			// Unless told otherwise, attempt to retrieve an API token.
			if (!arguments.skipAuth) {
				arguments.headers.api_token = getApiToken(arguments.key, arguments.reAuth);
			}

		</cfscript>


		<cfhttp method="#arguments.method#" url="#fullUrl#" result="httpResponse">
			<cfhttpparam type="header" name="Accept" value="application/json" />

			<cfswitch expression="#arguments.method#">
				<cfcase value="GET">
					<cfloop collection="#arguments.data#" item="itemkey">
						<cfhttpparam type="url" name="#itemkey#" value="#arguments.data[itemkey]#" />
					</cfloop>
				</cfcase>

				<cfcase value="PUT">
					<cfhttpparam type="header" name="Content-Type" value="application/json" />
					<cfhttpparam type="body" value="#serializeJSON(arguments.data)#" />
				</cfcase>

				<cfcase value="POST">
					<cfloop collection="#arguments.data#" item="itemkey">
						<cfhttpparam type="formField" name="#itemkey#" value="#arguments.data[itemkey]#" />
					</cfloop>
				</cfcase>
			</cfswitch>

			<cfloop collection="#arguments.headers#" item="itemkey">
				<cfhttpparam type="header" name="#itemkey#" value="#arguments.headers[itemkey]#" />
			</cfloop>

		</cfhttp>


		<cfif !structKeyExists(httpResponse, 'responseheader') ||
			 (structKeyExists(httpResponse, 'responseheader') && !structKeyExists(httpResponse.responseheader, 'status_code'))>
			<cfthrow type="wolfnet.api.client.ConnectionFailure"
					 message="Unable to connected to the API server." />
		</cfif>

		<cfset apiResponse = {
				requestUrl = fullUrl,
				requestMethod = arguments.method,
				requestData = arguments.data,
				responseStatusCode = httpResponse.responseheader.status_code,
				timestamp = now()
			} />

		<!--- If the response type is JSON attempt to deserialize the response body. --->
		<cfif httpResponse.mimetype eq "application/json">

			<cftry>
				<cfset apiResponse.responseData = deserializeJSON(httpResponse.filecontent) />

				<cfcatch type="any">
					<cfthrow type="wolfnet.api.client.InvalidJsonResponse"
					 		  message="An error occurred while attempting to deserialize the JSON API response."
					 		  extendedInfo="#serializeJSON(apiResponse)#" />
				</cfcatch>

			</cftry>

		</cfif>



		<!--- The API returned a 401 Unauthorized so throw an exception. --->
		<cfif apiResponse.responseStatusCode eq 401>
			<cfthrow type = "wolfnet.api.client.Unauthorized"
					 message = "#httpResponse.status_text#"
					 extendedInfo = "#serializeJSON(apiResponse)#" />

		<!--- The API returned a 403 Forbidden so throw an exception --->
		<cfelseif apiResponse.responseStatusCode eq 403>
			<cfthrow type = "wolfnet.api.client.Forbidden"
					 message = "#httpResponse.status_text#"
					 extendedInfo = "#serializeJSON(apiResponse)#" />

		<!--- The API returned a 400 Bad Response because the token it was given was not valid, so attempt to re-authenticated and perform the request again. --->
		<cfelseif apiResponse.responseStatusCode eq 400 && apiResponse.responseData.metadata.status.errorCode eq "Auth1005" && !arguments.reAuth>

			<cfreturn rawRequest(argumentCollection=arguments, reAuth=true) />

		<!--- We received an unexpected response from the API so throw an exception. --->
		<cfelseif apiResponse.responseStatusCode neq 200>
			<cfthrow type = "wolfnet.api.client.BadResponse"
					 message = "#apiResponse.responsedata.metadata.status.message#"
					 extendedInfo = "#serializeJSON(apiResponse)#" />

		</cfif>



		<cfreturn apiResponse />

	</cffunction>




	<!---
	This method uses the host value included during initialization and a resource string to create
	 a fully qualified API URL.
	 @param  {string}  resource  The URI endpoint being requested from the API.
	 @return {string}            A fully qualified API URL.
	--->
	<cffunction name="buildFullUrl" access="private" returntype="string" output="false">
		<cfargument name="resource" type="string" required="true" />

		<!--- TODO: The environment configuration needs to be updated to be only a host name and not include protocol.
		return "https://" & variables.apiHostName & arguments.resource;
		--->

		<cfreturn getHost() & arguments.resource />
	</cffunction>



	<!---
	This method validates that a provided resource string is formatted correctly.
	 @param  {string}  resource  The URI endpoint being requested from the API.
	 @return {Boolean}           Is the resource valid? true/false
	--->
	<cffunction name="isValidResource" access="private" returntype="boolean" output="false">
		<cfargument name="resource" type="string" required="true" />

		<!--- If the resource does not start with a leading slash it is not valid. --->
		<cfif left(arguments.resource, 1) neq "/">
			<cfreturn false />
		<cfelse>
			<cfreturn true />
		</cfif>

	</cffunction>



	<!---
	This method validates that a given method string matches one that is supported by the API.
	 @param  {string}  method  The HTTP method the request should be submitted as.
	 @return {Boolean}         Is the method valid? true/false
	--->
	<cffunction name="isValidMethod" access="private" returntype="boolean" output="false">
		<cfargument name="method" type="string" required="true" />

		<!--- If the resource does not start with a leading slash it is not valid. --->
		<cfif listFindNoCase("GET,POST,PUT,DELETE", arguments.method) eq 0>
			<cfreturn false />
		<cfelse>
			<cfreturn true />
		</cfif>

	</cffunction>



	<!---
	This method validates that the given data can be used with the API request.
	 @param  {struct}  data  Any query string or body data to be include with the request.
	 @return {Boolean}       Is the data valid? true/false
	--->
	<cffunction name="isValidData" access="private" returntype="boolean" output="false">
		<cfargument name="data" type="struct" required="true" />

		<cfset var valid = true />
		<cfset var key = "" />

		<cfscript>
			// Ensure that only simple values are included in the data. ie. strings, numbers, and booleans.
			for (key in arguments.data) {
				if (!isSimpleValue(arguments.data[key])) {
					valid = false;
					break;
				}
			}
		</cfscript>

		<cfreturn valid />

	</cffunction>




	<!---
	This method attempts to retrieve a token for use with an API request as authentication. If
	 possible it will retrieve the token from a persistent cache to minimize the number of API
	 requests that are made.
	 @param  {[type]} required string        key           [description]
	 @param  {[type]} boolean  force=false   [description]
	 @return {[type]}          [description]
	--->
	<cffunction name="getApiToken" access="private" returntype="any" output="false">
		<cfargument name="key" type="string" required="true" />
		<cfargument name="force" type="boolean" required="false" default="false" />

		<cfset var token = "" />
		<cfset var data = "" />
		<cfset var authResponse = "" />
		<cfset var requestArgs = structNew() />

		<cfscript>

			if (!arguments.force){
				token =  retrieveApiTokenDataFromCache(arguments.key);
			}

			// If a token was not retrieved from the cache perform an API request to retrieve a new one.
			if (token eq "") {
				data = {
					key = arguments.key,
					v = getVersion()
				};

				requestArgs = {
					key = arguments.key,
					resource = '/core/auth',
					method = "POST",
					data = data,
					skipAuth = true // Since we don't have a valid token we don't want to attempt to include it.
					};

				authResponse = rawRequest(argumentCollection=requestArgs);

				// TODO: Validate that the response includes the data we need.

				token = updateApiTokenDataCache(arguments.key, authResponse.responseData.data).api_token;

			}
		</cfscript>

		<cfreturn token />

	</cffunction>




	<!---
	This method retrieves a token from the application scope or an empty string if the token is
	 expired or none can be found.
	 @param  {string}  key  The client's API key.
	 @return {string}       [description]
	--->
	<cffunction name="retrieveApiTokenDataFromCache" access="private" returntype="string" output="false">
		<cfargument name="key" type="string" required="true" />

		<cfset var keyExists = "" />
		<cfset var tokenData = "" />
		<cfset var validData = "" />
		<cfset var token = "" />

		<cfscript>
			ensureTokenCacheExists();

			keyExists = structKeyExists(application[variables.appScopeKey].token, arguments.key);

			if (keyExists){
				tokenData = application[variables.appScopeKey].token[arguments.key];
			} else {
				tokenData = structNew();
			}

			validData = structKeyExists(tokenData, "api_token") && structKeyExists(tokenData, "expiration");

			// TODO: check if the token has or is about to become expired.

			if (validData) {
				token = application[variables.appScopeKey].token[arguments.key].api_token;
			} else {
				return "";
			}
		</cfscript>

		<cfreturn token />

	</cffunction>






	<!---
	This method stores API authentication token data in a request persistent cache.
	 @param  {string}  key        The client's API key.
	 @param  {struct}  tokenData  Token data to be cached.
	 @return {struct}             Return the same token data for function chaining.
	--->
	<cffunction name="updateApiTokenDataCache" access="private" returntype="struct" output="false">
		<cfargument name="key" type="string" required="true" />
		<cfargument name="tokenData" type="struct" required="true" />

		<cfset ensureTokenCacheExists() />
		<cfset application[variables.appScopeKey].token[arguments.key] = arguments.tokenData />

		<cfreturn arguments.tokenData />

	</cffunction>





	<!---
	This method ensures that the necessary structures are available to perform token data caching.
	 @return {void}
	--->
	<cffunction name="ensureTokenCacheExists" access="private" returntype="void" output="false">

		<cfscript>
			if (!structKeyExists(application, variables.appScopeKey)) {
				application[variables.appScopeKey] = {};
			}

			if (!structKeyExists(application[variables.appScopeKey], "token")) {
				application[variables.appScopeKey].token = {};
			}
		</cfscript>

	</cffunction>



	<!--- ACCESSOR METHODS -------------------------------------------------------------------- --->

	<cffunction name="getHost" access="public" returntype="string" output="false">
		<cfreturn variables.host />
	</cffunction>

	<cffunction name="setHost" access="public" returntype="void" output="false">
		<cfargument name="host" type="string" required="true" />
		<cfset variables.host = arguments.host />
	</cffunction>

	<cffunction name="getVersion" access="public" returntype="string" output="false">
		<cfreturn variables.version />
	</cffunction>

	<cffunction name="setVersion" access="public" returntype="void" output="false">
		<cfargument name="version" type="string" required="true" />
		<cfset variables.version = arguments.version />
	</cffunction>




</cfcomponent>
