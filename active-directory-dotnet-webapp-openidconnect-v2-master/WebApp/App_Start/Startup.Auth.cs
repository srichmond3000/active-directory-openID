using System;
using System.Web;
using Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Cookies;
using Microsoft.Owin.Security.OpenIdConnect;
using System.Configuration;
using System.Globalization;
using Microsoft.IdentityModel.Protocols;
using Microsoft.Owin.Security.Notifications;
using System.Threading.Tasks;
using System.IdentityModel.Tokens;
using Microsoft.Identity.Client;
using System.IdentityModel.Claims;
using WebApp_OpenIDConnect_DotNet.Models;
using WebApp.Utils;

namespace WebApp
{
    public partial class Startup
    {
        public static string clientId = ConfigurationManager.AppSettings["ida:ClientId"];
        private static string appKey = ConfigurationManager.AppSettings["ida:ClientSecret"];
        public static string aadInstance = ConfigurationManager.AppSettings["ida:AADInstance"];
        private static string redirectUri = ConfigurationManager.AppSettings["ida:RedirectUri"];

        public void ConfigureAuth(IAppBuilder app)
        {
            app.SetDefaultSignInAsAuthenticationType(CookieAuthenticationDefaults.AuthenticationType);

            app.UseCookieAuthentication(new CookieAuthenticationOptions());

            app.UseOAuth2CodeRedeemer(
                new OAuth2CodeRedeemerOptions
                {
                    ClientId = clientId,
                    ClientSecret = appKey,
                    RedirectUri = redirectUri
                });

            app.UseOpenIdConnectAuthentication(
                new OpenIdConnectAuthenticationOptions
                {
                    // The `Authority` represents the v2.0 endpoint - https://login.microsoftonline.com/common/v2.0
                    // The `Scope` describes the initial permissions that your app will need.  See https://azure.microsoft.com/documentation/articles/active-directory-v2-scopes/                    
                    ClientId = clientId,
                    Authority = String.Format(CultureInfo.InvariantCulture, aadInstance, "common", "/v2.0"),
                    RedirectUri = redirectUri,
                    Scope = "openid, profile, offline_access, Mail.Read, Mail.Send",
                    PostLogoutRedirectUri = redirectUri,
                    ResponseType = "code id_token",
                    TokenValidationParameters = new TokenValidationParameters
                    {
                        ValidateIssuer = false,
                    },
                    Notifications = new OpenIdConnectAuthenticationNotifications
                    {
                        AuthorizationCodeReceived = OnAuthorization,
                        AuthenticationFailed = OnAuthenticationFailed

                    }
                });
        }

        private async Task OnAuthorization(AuthorizationCodeReceivedNotification context)
        {
            var code = context.Code;
            string Authority = String.Format(CultureInfo.InvariantCulture, aadInstance, "common", "/v2.0");
            string signedInUserID = context.AuthenticationTicket.Identity.FindFirst(ClaimTypes.NameIdentifier).Value;
            ClientCredential clientCred = new ClientCredential(appKey);
            TokenCache tokenCache = new MSALSessionCache(signedInUserID, context.OwinContext.Environment["System.Web.HttpContextBase"] as HttpContextBase).GetMsalCacheInstance();
            ConfidentialClientApplication cca = new ConfidentialClientApplication(clientId, Authority, redirectUri, clientCred, tokenCache, null);
            try
            {
                string[] scopes = { "Mail.Read" };
                AuthenticationResult result = await cca.AcquireTokenByAuthorizationCodeAsync(code, scopes);
            }
            catch (Exception eee)
            {

            }
        }

        private Task OnAuthenticationFailed(AuthenticationFailedNotification<OpenIdConnectMessage, OpenIdConnectAuthenticationOptions> notification)
        {
            notification.HandleResponse();
            notification.Response.Redirect("/Error?message=" + notification.Exception.Message);
            return Task.FromResult(0); 
        }
    }
}