using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.Http.Filters;
using System.Configuration;
using System.Net.Http;
using System.Net;

public class NGAuthorizationAttribute : ActionFilterAttribute, IActionFilter
{
    private string AllUserIds = ConfigurationManager.AppSettings["UserIds"];
    private string AllUserPwds = ConfigurationManager.AppSettings["UserPwds"];

    public override void OnActionExecuting(System.Web.Http.Controllers.HttpActionContext actionContext)
    {
        IEnumerable<string> lsHeaders;
        try
        {
            var checkUserExists = actionContext.Request.Headers.TryGetValues("Authorization", out lsHeaders);
            if (!string.IsNullOrEmpty(AllUserIds) && !string.IsNullOrEmpty(AllUserPwds) && checkUserExists)
            {
                CMSSanaApi.Models.ICryptography crypt = new CMSSanaApi.Models.Cryptography();
                string cipherTestTemp, idAndPwd = "";
                string authString = lsHeaders.FirstOrDefault();
                string algo = authString.Substring(0, authString.IndexOf(' '));
                if (!string.IsNullOrEmpty(algo) && algo.ToUpper() == "AES")
                {
                    cipherTestTemp = authString.Substring(authString.IndexOf(' ') + 1, authString.Length - (algo.Length + 1));
                    idAndPwd = crypt.AesDecrypt(cipherTestTemp);
                }
                else if (!string.IsNullOrEmpty(algo) && algo.ToUpper() == "BASIC")
                {
                    cipherTestTemp = authString.Substring(authString.IndexOf(' ') + 1, authString.Length - (algo.Length + 1));
                    var temp = Convert.FromBase64String(cipherTestTemp);
                    idAndPwd = System.Text.Encoding.UTF8.GetString(temp);
                }
                else
                {
                    actionContext.Response = actionContext.Request.CreateResponse(HttpStatusCode.BadRequest, "Incorrect Authorization Algorithm.");
                }

                if (idAndPwd.Split(':').Length == 2)
                {
                    string resultUserId = AllUserIds.Split(',').Where(col => col == idAndPwd.Split(':')[0]).FirstOrDefault();
                    string resultPwd = AllUserPwds.Split(',').Where(col => col == idAndPwd.Split(':')[1]).FirstOrDefault();
                    if (resultUserId != null && resultPwd != null && resultUserId == idAndPwd.Split(':')[0] && resultPwd == idAndPwd.Split(':')[1])
                    {
                        base.OnActionExecuting(actionContext);
                    }
                    else
                    {
                        actionContext.Response = actionContext.Request.CreateResponse(HttpStatusCode.Unauthorized, "Invalid user id and password for web api access.");
                    }
                }
                else
                {
                    actionContext.Response = actionContext.Request.CreateResponse(HttpStatusCode.BadRequest, "Unable to get user id and password.");
                }
            }
            else
            {
                actionContext.Response = actionContext.Request.CreateResponse(HttpStatusCode.Unauthorized, "Unauthorize access of web api.");
            }
        }
        catch (Exception ex)
        {
            actionContext.Response = actionContext.Request.CreateErrorResponse(HttpStatusCode.BadRequest, ex);
        }
    }
}