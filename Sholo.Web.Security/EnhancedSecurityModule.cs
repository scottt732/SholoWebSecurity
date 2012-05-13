/*
 * Copyright 2010-2012, Scott Holodak, Alex Friedman
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 * http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

using System;
using System.Security.Cryptography;
using System.Text.RegularExpressions;
using System.Web;
using System.Web.Security;
using Sholo.Web.Security.Analysis;
using Sholo.Web.Security.Authentication.User;

namespace Sholo.Web.Security
{
    /// <summary>
    /// HttpModule implementation to enhance security of ASP.NET applications
    /// </summary>
    public sealed class EnhancedSecurityModule : IHttpModule
    {
        /// <summary>
        /// Performs initializations / startup functionality when an instance of this HttpModule
        /// is being created.
        /// </summary>
        /// <param name="context">the current HttpApplication</param>        
        public void Init(HttpApplication context)
        {
            // Register our event handlers.  These are fired on every HttpRequest.
            context.BeginRequest += OnBeginRequest;
            context.EndRequest += OnEndRequest;
            context.Error += OnError;
        }

        /// <summary>
        /// Performs cleanup when an instance of this HttpModule is being destroyed.
        /// </summary>
        public void Dispose()
        {
        }

        /// <summary>
        /// Intercepts the beginning of the request pipeline and performs analysis
        /// and manipulation of FormsAuthenticationCookies prior to the 
        /// FormsAuthenticationModule's AuthenticateRequest firing.  It stores some
        /// information about the request in the Context.Items collection for analysis
        /// later in the request pipeline execution.
        /// </summary>
        /// <param name="sender">The HttpApplication that sent the request</param>
        /// <param name="e">Not used</param>
        private static void OnBeginRequest(object sender, EventArgs e)
        {
            HttpContext context = HttpContext.Current;
            HttpRequest request = context.Request;
            HttpResponse response = context.Response;

            if (request.RawUrl.Contains(".axd"))
            {
                context.Items["BewareOfCryptographicException"] = "true";                
            }

            if (request.QueryString["aspxerrorpath"] != null)
            {
                EnhancedSecurity.DelaySuspiciousResponse();
                string newUrl = RemovQueryStringArg("aspxerrorpath");
                response.Redirect(newUrl, false);
                response.End();
            }
              
            EnhancedSecurity.Initialize();                        

            HttpCookie formsAuthCookie = context.Request.Cookies[FormsAuthentication.FormsCookieName];
            RequestAnalysis analysis = RequestAnalyzer.AnalyzeRequest(formsAuthCookie, RequestLifecyclePhase.BeginRequest, true);

            if (analysis.RequestIsAuthenticated)
            {
                if (analysis.RequestIsMalicious)
                {
                    EnhancedSecurity.SetFormsAuthStatus(FormsAuthenticationStatus.Invalid);
                    EnhancedSecurity.DelayMaliciousResponse();
                }
                else if (!analysis.RequestIsValid)
                {
                    EnhancedSecurity.SetFormsAuthStatus(FormsAuthenticationStatus.Invalid);
                }
                else
                {
                    EnhancedSecurity.SetFormsAuthStatus(FormsAuthenticationStatus.Valid);

                    if (UserAuthentication.Enabled)
                    {
                        // analyzer.FormsAuthenticationCookie.Value;
                        context.Items["OriginalCookieValue"] = analysis.FormsAuthenticationCookie.Value;
                        context.Items["ServerUserData"] = analysis.FormsAuthenticationTicket.UserData;
                        context.Items["ServerTicketKey"] = analysis.UserAuthenticationTicket.Key;
                        context.Items["UserAuthenticationTicket"] = analysis.UserAuthenticationTicket;

                        // Substitute actual UserData from serverTicket
                        FormsAuthenticationTicket tempFormsAuthTicket = UserAuthentication.CreateFormsAuthTicket(
                            analysis.UserAuthenticationTicket.Username,
                            analysis.UserAuthenticationTicket.CookiePath,
                            analysis.UserAuthenticationTicket.TicketUserData, 
                            analysis.UserAuthenticationTicket.TicketIssueDate,
                            analysis.FormsAuthenticationTicket.Expiration,
                            false
                        );

                        UserAuthentication.SetAuthCookie(tempFormsAuthTicket, true, false);
                    }
                }
            }
            else
            {
                if (analysis.RequestIsMalicious)
                {
                    EnhancedSecurity.SetFormsAuthStatus(FormsAuthenticationStatus.Invalid);
                    EnhancedSecurity.DelayMaliciousResponse();
                }
                else
                {
                    EnhancedSecurity.SetFormsAuthStatus(FormsAuthenticationStatus.NotFound);
                }
            }
        }

        /// <summary>
        /// Detects the creation of a FormsAuthenticationCookie and FormsAuthenticationTicket
        /// during the processing of the current request (i.e., PostBack of Login page/action),
        /// records the state of both in a UserAuthenticationTicket, and adds it to the 
        /// Provider.
        /// 
        /// In the event that this request was already authenticated, it detects and handles 
        /// sliding expiration on the Provider.
        /// </summary>
        /// <param name="sender">The HttpApplication that sent the request</param>
        /// <param name="e">Not used</param>
        private static void OnEndRequest(object sender, EventArgs e)
        {
            // EnhancedSecurity.InterceptFormsAuthenticationCookie();
            FormsAuthenticationStatus status = EnhancedSecurity.GetFormsAuthStatus();

            HttpContext context = HttpContext.Current;
            HttpRequest request = context.Request;
            HttpResponse response = context.Response;

            /* TODO: Remove this once working */
            /*
            if (request.RawUrl.Contains("WebResource.axd"))
            {
                return;
            }
            */
              
            if (status == FormsAuthenticationStatus.NotFound || status == FormsAuthenticationStatus.Invalid)
            {
                RequestAnalysis preAnalyzer = RequestAnalyzer.RetrieveAnalysis(RequestLifecyclePhase.BeginRequest);
                RequestAnalysis postAnalyzer = RequestAnalyzer.AnalyzeRequest(response.Cookies[FormsAuthentication.FormsCookieName], RequestLifecyclePhase.EndRequest, true);

                if (preAnalyzer != null)
                {
                    ComparisonResult result = RequestAnalyzer.Compare(preAnalyzer, postAnalyzer);

                    if (result == ComparisonResult.UnauthenticatedRequest)
                    {
                        // Nothing to do   
                    }
                    else if (result == ComparisonResult.AuthenticatedRequest)
                    {
                        // Nothing to do   
                    }
                    else if (result == ComparisonResult.LoginRequest)
                    {
                        // Store the ticket on the server

                        string hash = UserAuthentication.CalculateFormsAuthTicketHash(postAnalyzer.FormsAuthenticationTicket);
                        string key = Guid.NewGuid().ToString();

                        UserAuthenticationTicket serverAuthTicket = new UserAuthenticationTicket
                        {
                            Key = key,
                            Username = postAnalyzer.FormsAuthenticationTicket.Name,
                            HostAddress = request.UserHostAddress,
                            CookieDomain = postAnalyzer.FormsAuthenticationCookie.Domain,
                            CookiePath = postAnalyzer.FormsAuthenticationCookie.Path,
                            CookieSecure = postAnalyzer.FormsAuthenticationCookie.Secure,
                            TicketExpiration = postAnalyzer.FormsAuthenticationTicket.Expiration,
                            CookieName = postAnalyzer.FormsAuthenticationCookie.Name,
                            TicketIsPersistent = postAnalyzer.FormsAuthenticationTicket.IsPersistent,
                            TicketIssueDate = postAnalyzer.FormsAuthenticationTicket.IssueDate,
                            TicketUserData = postAnalyzer.FormsAuthenticationTicket.UserData,
                            TicketVersion = postAnalyzer.FormsAuthenticationTicket.Version,
                            TicketHash = hash
                        };

                        UserAuthentication.Provider.InsertTicket(serverAuthTicket, postAnalyzer.FormsAuthenticationTicket.Expiration);

                        FormsAuthenticationTicket newFormsAuthTicket = UserAuthentication.CreateFormsAuthTicket(
                            postAnalyzer.FormsAuthenticationTicket.Name,
                            postAnalyzer.FormsAuthenticationCookie.Path,
                            hash + ";" + key,
                            postAnalyzer.FormsAuthenticationTicket.IssueDate,
                            postAnalyzer.FormsAuthenticationTicket.Expiration,
                            false
                        );

                        UserAuthentication.ClearAuthCookie();
                        UserAuthentication.SetAuthCookie(newFormsAuthTicket, true, true);
                    }
                    else if (result == ComparisonResult.LogoutRequest)
                    {
                        if (preAnalyzer.UserAuthenticationTicket != null)
                        {
                            UserAuthentication.Provider.RevokeTicket(preAnalyzer.UserAuthenticationTicket.Key);
                        }
                        UserAuthentication.ClearAuthCookie();

                        // Revoke the ticket on the server
                    }
                    else if (result == ComparisonResult.MaliciousRequest)
                    {
                        UserAuthentication.ClearAuthCookie();

                        // Hmm.. what to do
                        // System.Diagnostics.Debugger.Break();
                    }
                }
            }
            else if (status == FormsAuthenticationStatus.Valid)
            {
                // TODO: Handle sliding ticket expiration
                // UserAuthentication.Provider.UpdateTicketExpiration();
            }
        }

        /// <summary>
        /// Detects a CryptographicException and delays the response to reduce the likelihood
        /// of a successful padding oracle exploit attack.
        /// </summary>
        /// <param name="sender">The HttpApplication that sent the request</param>
        /// <param name="e">Not used</param>
        private static void OnError(object sender, EventArgs e)
        {
            HttpContext context = HttpContext.Current;
            HttpRequest request = context.Request;
            HttpResponse response = context.Response;
            HttpServerUtility server = context.Server;
            Exception exception = server.GetLastError();

            if (exception is CryptographicException)
            {
                if (context.Items["BewareOfCryptographicException"] != null && context.Items["BewareOfCryptographicException"].ToString() == "true")
                {
                    EnhancedSecurity.DelayCryptographicExceptionResponse();
                    response.Clear();
                    response.ContentType = "text/html";
                    response.Output.WriteLine("<html><head><title>No</title></head><body>This isn't the oracle you're looking for.</body></html>");
                    response.End();
                }
                else
                {
                    EnhancedSecurity.DelaySuspiciousResponse();
                }
            }
            else
            {
                if (request.RawUrl.Contains(".axd"))
                {
                    context.ClearError();
                    response.StatusCode = 404;
                    throw new HttpException(404, "The resource you are looking for has been removed.");
                }
            }
        }

        #region Helper Methods
        private static string RemovQueryStringArg(string queryStringArg)
        {
            HttpContext context = HttpContext.Current;
            HttpRequest request = context.Request;

            string argValue = request.QueryString[queryStringArg];
            if (argValue != null)
            {
                string newUrl = Regex.Replace(request.RawUrl, Regex.Escape(queryStringArg + "=" + argValue), string.Empty, RegexOptions.IgnoreCase).Replace("?&", "?").Replace("&&", "&");
                return newUrl.EndsWith("?") ? newUrl.Substring(0, newUrl.Length - 1) : newUrl;
            }
            return request.RawUrl;
        }
        #endregion
    }
}