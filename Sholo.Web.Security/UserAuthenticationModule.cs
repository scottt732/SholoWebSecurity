/*
 * Copyright 2010-2012, Scott Holodak
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
using System.Text.RegularExpressions;
using System.Web;
using System.Web.Security;
using Sholo.Web.Security.Analysis;
using Sholo.Web.Security.Ticket;

namespace Sholo.Web.Security
{
    public class UserAuthenticationModule : IHttpModule
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
            UserAuthentication.Initialize();
            UserAuthentication.Provider.RemoveExpiredTickets();
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
                FormsAuthenticationAnalyzer preAnalyzer = context.Items["preAnalyzer"] as FormsAuthenticationAnalyzer;
                FormsAuthenticationAnalyzer postAnalyzer = new FormsAuthenticationAnalyzer(response.Cookies[FormsAuthentication.FormsCookieName], true);

                if (preAnalyzer != null)
                {
                    ComparisonResult result = FormsAuthenticationAnalyzer.Compare(preAnalyzer, postAnalyzer);

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

                        UserAuthenticationTicket userAuthTicket = new UserAuthenticationTicket
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

                        UserAuthentication.Provider.InsertTicket(userAuthTicket, postAnalyzer.FormsAuthenticationTicket.Expiration);

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
    }
}
