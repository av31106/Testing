using System;
using System.Collections.Generic;
using System.Configuration;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using System.Web;

public class APIKeyHandler : DelegatingHandler
{
    private string AllApiKeys = ConfigurationManager.AppSettings["ApiKeys"];

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        //this is for only gethash code.
        if (request.RequestUri.ToString().Contains("CalculateHash/GetHash") ||
            request.RequestUri.ToString().Contains("CalculateHash/GetHashIos"))
        {
            //Allow the request to process further down the pipeline.
            var responseTemp = await base.SendAsync(request, cancellationToken);

            //Return the response back up the chain.
            return responseTemp;
        }

        bool isValidAPIKey = false;
        IEnumerable<string> lsHeaders;
        //Validate that the api key exists.
        var checkApiKeyExists = request.Headers.TryGetValues("Api-Key", out lsHeaders);
        if (!string.IsNullOrEmpty(AllApiKeys) && checkApiKeyExists)
        {
            string apiKey = lsHeaders.FirstOrDefault();
            string resultKey = AllApiKeys.Split(',').Where(col => col == apiKey).FirstOrDefault();
            if (resultKey != null && resultKey == apiKey)
                isValidAPIKey = true;
        }

        //If the key is not valid, return an http status code.
        if (!isValidAPIKey)
            return request.CreateResponse(HttpStatusCode.Forbidden, "Invalid Api Key.");

        //Allow the request to process further down the pipeline.
        var response = await base.SendAsync(request, cancellationToken);

        //Return the response back up the chain.
        return response;
    }
}
