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
using System.Web;
using System.Web.Security;
using Sholo.Web.Security.Authentication.User;

namespace Sholo.Web.Security.Analysis
{
    /// <summary>
    /// Utility class to analyze the state of FormsAuthenticationTickets and FormsAuthenticationCookies
    /// </summary>
    [Serializable]
    public class FormsAuthenticationAnalyzer
    {
        /// <summary>
        /// Creates a new instance of a FormsAuthenticationCookieAnalyzer
        /// </summary>
        /// <param name="formsAuthenticationCookie">The formsAuthenticationCookie to inspect</param>
        /// <param name="isEndRequest">Indicates whether the analysis is occurring during the EndRequest phase of the execution pipeline</param>
        public FormsAuthenticationAnalyzer(HttpCookie formsAuthenticationCookie, bool isEndRequest)
        {
            EnhancedSecurity.Initialize();

            Context = new ContextInformation();
            FormsAuthenticationCookieResult = AnalyzeFormsAuthenticationCookie(formsAuthenticationCookie);
            if (UserAuthentication.Enabled)
            {
                FormsAuthenticationTicketResult = AnalyzeFormsAuthenticationTicket(FormsAuthenticationCookieResult, true, isEndRequest);
                UserAuthenticationTicketResult = AnalyzeServerAuthenticationTicket(Context, FormsAuthenticationCookieResult, FormsAuthenticationTicketResult, UserAuthentication.EnforceClientHostAddressValidation);
            }
            else
            {
                FormsAuthenticationTicketResult = AnalyzeFormsAuthenticationTicket(FormsAuthenticationCookieResult, false, isEndRequest);
                UserAuthenticationTicketResult = new UserAuthenticationTicketAnalysis();
            }
        }

        
        /// <summary>
        /// Context information derived from the current request
        /// </summary>
        public ContextInformation Context { get; protected set; }
        
        /// <summary>
        /// Analysis results of the FormsAuthenticationCookie validity & security
        /// </summary>
        public FormsAuthenticationCookieAnalysis FormsAuthenticationCookieResult { get; protected set; }
        
        /// <summary>
        /// Analysis results of the FormsAuthenticationTicket validity & security
        /// </summary>
        public FormsAuthenticationTicketAnalysis FormsAuthenticationTicketResult { get; protected set; }
        
        /// <summary>
        /// Analysis result of the UserAuthenticationTicket validity & security
        /// </summary>
        public UserAuthenticationTicketAnalysis UserAuthenticationTicketResult { get; private set; }

        /// <summary>
        /// The FormsAuthenticationCookie inspected
        /// </summary>
        public HttpCookie FormsAuthenticationCookie
        {
            get
            {
                return FormsAuthenticationCookieResult.FormsAuthenticationCookie;
            }
        }

        /// <summary>
        /// The FormsAuthenticationTicket inspected
        /// </summary>
        public FormsAuthenticationTicket FormsAuthenticationTicket
        {
            get
            {
                return FormsAuthenticationTicketResult.FormsAuthenticationTicket;
            }
        }

        /// <summary>
        /// The UserAuthenticationTicket inspected
        /// </summary>
        public UserAuthenticationTicket UserAuthenticationTicket
        {
            get
            {
                return UserAuthenticationTicketResult.UserAuthenticationTicket;
            }
        }

        /// <summary>
        /// Indicates whether the current request is authenticated
        /// </summary>
        public bool RequestIsAuthenticated
        {
            get
            {
                // return new ContextInformation().IsAuthenticated;
                return FormsAuthenticationTicket != null && FormsAuthenticationTicketResult != null && FormsAuthenticationTicketResult.IsValid;
            }
        }

        /// <summary>
        /// Indicates whether the current request is valid
        /// </summary>
        public bool RequestIsValid
        {
            get
            {
                return
                    FormsAuthenticationCookieResult.IsValid
                    && FormsAuthenticationTicketResult.IsValid
                    &&
                    (
                        (UserAuthentication.Enabled && UserAuthenticationTicketResult.IsValid)
                    || !UserAuthentication.Enabled
                    );
            }
        }

        /// <summary>
        /// Indicates whether the current request is malicious
        /// </summary>
        public bool RequestIsMalicious
        {
            get
            {
                return
                    FormsAuthenticationCookieResult.IsMalicious
                    || FormsAuthenticationTicketResult.IsMalicious
                    || (UserAuthentication.Enabled && UserAuthenticationTicketResult.IsMalicious);
            }
        }

        /// <summary>
        /// Perform analysis of the FormsAuthenticationCookie supplied
        /// </summary>
        /// <param name="cookie">The FormsAuthenticationCookie to validate</param>
        /// <returns>A FormsAuthenticationCookieAnalysis object containing the results of the analysis</returns>
        public static FormsAuthenticationCookieAnalysis AnalyzeFormsAuthenticationCookie(HttpCookie cookie)
        {
            FormsAuthenticationCookieAnalysis analysis = new FormsAuthenticationCookieAnalysis { CookieExists = (cookie != null) };

            if (analysis.CookieExists)
            {
                FormsAuthenticationTicket formsAuthenticationTicket = null;

                analysis.FormsAuthenticationCookie = cookie;
                if (cookie != null)
                {
                    analysis.IsCookieFormsAuthCookie = (cookie.Name == FormsAuthentication.FormsCookieName);
                    analysis.IsDomainValid = (cookie.Domain == FormsAuthentication.CookieDomain);
                    analysis.IsExpired = (DateTime.Now.CompareTo(cookie.Expires) > 0 && cookie.Expires.CompareTo(DateTime.MinValue) != 0);
                    analysis.IsPathValid = (cookie.Path == FormsAuthentication.FormsCookiePath);
                    analysis.IsSecureValid = (cookie.Secure == FormsAuthentication.RequireSSL);
                    analysis.HasValue = !string.IsNullOrEmpty(cookie.Value);
                }

                analysis.ValueDecrypts = analysis.HasValue;
                if (analysis.HasValue)
                {
                    try
                    {
                        if (cookie != null && cookie.Value != null)
                        {
                            formsAuthenticationTicket = FormsAuthentication.Decrypt(cookie.Value);

                            if (formsAuthenticationTicket != null)
                            {
                                analysis.ValueDecrypts = true;
                                analysis.SetFormsAuthenticationTicket(formsAuthenticationTicket);
                            }
                        }
                        else
                        {
                            analysis.ValueDecrypts = false;
                        }
                    }
                    catch
                    {
                        analysis.ValueDecrypts = false;
                    }
                }

                analysis.IsValid =
                    analysis.IsCookieFormsAuthCookie &&
                    analysis.IsDomainValid &&
                    !analysis.IsExpired &&
                    analysis.IsPathValid &&
                    analysis.IsSecureValid &&
                    ((analysis.HasValue && analysis.ValueDecrypts && formsAuthenticationTicket != null) || !analysis.HasValue);

                if (!analysis.IsValid)
                {
                    analysis.IsMalicious =
                        !analysis.IsCookieFormsAuthCookie ||
                        !analysis.IsDomainValid ||
                        !analysis.IsPathValid ||
                        (analysis.HasValue && !analysis.ValueDecrypts) ||
                        !analysis.IsSecureValid;
                }
            }
            else
            {
                analysis.IsValid = false;
                analysis.IsMalicious = false;
            }

            return analysis;
        }

        /// <summary>
        /// Perform analysis of the FormsAuthenticationTicket supplied
        /// </summary>
        /// <param name="cookieAnalysis">The result of the FormsAuthenticationCookie analysis</param>
        /// <param name="enforceServerAuthenticationTicketValidation">Indicates whether to enforce UserAuthenticationTicket validation</param>
        /// <param name="isEndRequest">Indicates whether the analysis is occurring during the EndRequest phase of the execution pipeline</param>
        /// <returns>A FormsAuthenticationTicketAnalysis object containing the results of the analysis</returns>
        public static FormsAuthenticationTicketAnalysis AnalyzeFormsAuthenticationTicket(FormsAuthenticationCookieAnalysis cookieAnalysis, bool enforceServerAuthenticationTicketValidation, bool isEndRequest)
        {
            FormsAuthenticationTicketAnalysis analysis = new FormsAuthenticationTicketAnalysis();
            FormsAuthenticationTicket ticket = cookieAnalysis.GetFormsAuthenticationTicket();

            analysis.TicketExists = (ticket != null);
            if (analysis.TicketExists)
            {
                if (cookieAnalysis.HasValue && ticket != null)
                {
                    DateTime netFramework2ReleaseDate = new DateTime(2006, 1, 22);

                    analysis.FormsAuthenticationTicket = ticket;
                    analysis.TicketExists = true;
                    analysis.CookiePathMatches = (ticket.CookiePath == FormsAuthentication.FormsCookiePath);
                    analysis.HasUserData = (!string.IsNullOrEmpty(ticket.UserData));
                    analysis.IsExpired = ticket.Expired || ticket.Expiration.CompareTo(DateTime.Now) < 0;
                    analysis.IsIssueDateValid = (ticket.IssueDate.CompareTo(netFramework2ReleaseDate) > 0);
                    analysis.IsNameValid = (!string.IsNullOrEmpty(ticket.Name)); // && ticket.Name == ContextInformation.ThreadCurrentPrincipalIdentityName && ticket.Name == ContextInformation.UserIdentityName);
                    analysis.HasUserData = !string.IsNullOrEmpty(ticket.UserData);

                    analysis.IsPersistenceValid = true; /* TODO: See how to check this in FormsAuthentication */

                    string guid = null;
                    if (ticket.UserData != null && ticket.UserData.Length == UserAuthentication.HashAlgorithmStringLength + UserAuthentication.GuidStringLength + 1 && ticket.UserData[UserAuthentication.HashAlgorithmStringLength] == ';')
                    {
                        string[] parts = ticket.UserData.Split(';');
                        if (parts.Length == 2)
                        {
                            string hash = parts[0];
                            analysis.UserDataContainsHash = true;
                            for (int i = 0; i < hash.Length; i++)
                            {
                                if (!((hash[i] >= 0x30 && hash[i] <= 0x39) /* 0-9 */
                                    /* || (hash[i] >= 0x41 && hash[i] <= 0x46)      A-F   (lowercase only!) */
                                        || (hash[i] >= 0x61 && hash[i] <= 0x66))) /* a-f */
                                {
                                    analysis.UserDataContainsHash = false;
                                    break;
                                }
                            }

                            if (analysis.UserDataContainsHash)
                            {
                                analysis.TicketHash = hash;
                                string actualHash = UserAuthentication.CalculateFormsAuthTicketHash(ticket);
                                analysis.IsUserDataHashValid = (hash == actualHash);
                            }

                            guid = parts[1];
                            try
                            {
                                #pragma warning disable 168
                                Guid testGuidCreation = new Guid(guid);
                                #pragma warning restore 168
                                
                                analysis.ServerKey = parts[1];
                                analysis.UserDataContainsServerAuthenticationTicketKey = true;
                            }
                            catch (FormatException)
                            {
                                analysis.UserDataContainsServerAuthenticationTicketKey = false;
                            }
                            catch (OverflowException)
                            {
                                analysis.UserDataContainsServerAuthenticationTicketKey = false;
                            }
                            catch (ArgumentNullException)
                            {
                                analysis.UserDataContainsServerAuthenticationTicketKey = false;
                            }
                        }
                        else
                        {
                            analysis.UserDataContainsHash = false;
                            analysis.UserDataContainsServerAuthenticationTicketKey = false;
                        }
                    }
                    else
                    {
                        analysis.UserDataContainsHash = false;
                        analysis.UserDataContainsServerAuthenticationTicketKey = false;
                    }

                    if (!string.IsNullOrEmpty(guid))
                    {
                        UserAuthenticationTicket serverAuthenticationTicket = UserAuthentication.Provider.GetTicket(guid);
                        if (serverAuthenticationTicket != null)
                        {
                            analysis.UserDataServerAuthenticationTicketKeyFound = true;
                            analysis.SetServerAuthenticationTicket(serverAuthenticationTicket);
                        }
                        else
                        {
                            analysis.UserDataServerAuthenticationTicketKeyFound = false;
                        }
                    }
                    else
                    {
                        analysis.UserDataServerAuthenticationTicketKeyFound = false;
                    }

                    analysis.IsVersionValid = (ticket.Version == 2);

                    analysis.IsValid =
                        analysis.TicketExists &&
                        analysis.CookiePathMatches &&
                        !analysis.IsExpired &&
                        analysis.IsIssueDateValid &&
                        analysis.IsNameValid &&
                        analysis.IsPersistenceValid &&
                        analysis.IsVersionValid;

                    /*
                        &&
                        (!enforceServerAuthenticationTicketValidation || analysis.HasUserData) &&
                        (!enforceServerAuthenticationTicketValidation || analysis.UserDataContainsHash) &&
                        (!enforceServerAuthenticationTicketValidation || analysis.IsUserDataHashValid) &&
                        (!enforceServerAuthenticationTicketValidation || analysis.UserDataContainsServerAuthenticationTicketKey) &&
                        (!enforceServerAuthenticationTicketValidation || analysis.UserDataServerAuthenticationTicketKeyFound) &&
                        (!enforceServerAuthenticationTicketValidation || UserAuthenticationTicket != null);
                    */

                    if (!analysis.IsValid)
                    {
                        analysis.IsMalicious =
                            !analysis.CookiePathMatches ||
                            !analysis.IsPersistenceValid ||
                            !analysis.IsIssueDateValid ||
                            !analysis.IsNameValid ||
                            !analysis.IsVersionValid;

                        /*
                        if (!analysis.IsMalicious && enforceServerAuthenticationTicketValidation && !isEndRequest)
                        {
                            analysis.IsMalicious = 
                                !analysis.HasUserData || 
                                !analysis.UserDataContainsHash || 
                                !analysis.IsUserDataHashValid || 
                                !analysis.UserDataContainsServerAuthenticationTicketKey;
                        }
                        */
                    }
                }
                else
                {
                    analysis.IsValid = false;
                    analysis.IsMalicious = false;
                }
            }
            else
            {
                analysis.IsValid = false;
                analysis.IsMalicious = false;
            }
            return analysis;
        }

        /// <summary>
        /// Perform analysis of the UserAuthenticationTicket supplied
        /// </summary>
        /// <param name="contextInformation">Context information derived from the current request</param>
        /// <param name="cookieAnalysis">The result of the FormsAuthenticationCookie analysis</param>
        /// <param name="ticketAnalysis">The result of the FormsAuthenticationTicket analysis</param>
        /// <param name="userAuthenticationTicket">The UserAuthenticationTicket to inspect</param>
        /// <param name="enforceHostAddressValidation">Indicates whether to enforce that the ticket was provided from the same IP address for which it created</param>
        /// <returns>A UserAuthenticationTicketAnalysis object containing the results of the analysis</returns>
        public static UserAuthenticationTicketAnalysis AnalyzeServerAuthenticationTicket(ContextInformation contextInformation, FormsAuthenticationCookieAnalysis cookieAnalysis, FormsAuthenticationTicketAnalysis ticketAnalysis, UserAuthenticationTicket userAuthenticationTicket, bool enforceHostAddressValidation)
        {
            UserAuthenticationTicketAnalysis analysis = new UserAuthenticationTicketAnalysis();
            HttpCookie formsAuthCookie = cookieAnalysis.FormsAuthenticationCookie;
            FormsAuthenticationTicket formsAuthTicket = ticketAnalysis.FormsAuthenticationTicket;

            analysis.TicketExists = (userAuthenticationTicket != null);
            if (analysis.TicketExists)
            {
                analysis.UserAuthenticationTicket = userAuthenticationTicket;
                if (userAuthenticationTicket != null)
                {
                    analysis.CookieDomainMatch = (userAuthenticationTicket.CookieDomain == formsAuthCookie.Domain);
                    analysis.CookiePathMatch = (userAuthenticationTicket.CookiePath == formsAuthTicket.CookiePath && formsAuthTicket.CookiePath == formsAuthCookie.Path);
                    analysis.CookieSecureMatch = (userAuthenticationTicket.CookieSecure == formsAuthCookie.Secure);
                    /* analysis.ExpirationMatch = (DateTime.Compare(UserAuthenticationTicket.TicketExpiration, formsAuthTicket.Expiration) == 0 && DateTime.Compare(formsAuthTicket.Expiration, formsAuthCookie.Expires) == 0); */
                    analysis.CookieNameMatch = (userAuthenticationTicket.CookieName == formsAuthCookie.Name);
                    analysis.TicketPersistenceMatch = (userAuthenticationTicket.TicketIsPersistent == formsAuthTicket.IsPersistent);
                    analysis.TicketIssueDateMatch = (DateTime.Compare(userAuthenticationTicket.TicketIssueDate, formsAuthTicket.IssueDate) == 0);
                    analysis.TicketUsernameMatch = (userAuthenticationTicket.Username == formsAuthTicket.Name);
                    analysis.TicketVersionMatch = (userAuthenticationTicket.TicketVersion == formsAuthTicket.Version);
                    analysis.TicketHashMatch = (userAuthenticationTicket.TicketHash == ticketAnalysis.TicketHash);
                    analysis.HostAddressMatch = (userAuthenticationTicket.HostAddress == contextInformation.HostAddress);
                }

                analysis.IsValid =
                    analysis.CookieDomainMatch &&
                    analysis.CookiePathMatch &&
                    analysis.CookieSecureMatch &&
                    /* analysis.ExpirationMatch && */
                    analysis.CookieNameMatch &&
                    analysis.TicketPersistenceMatch &&
                    analysis.TicketIssueDateMatch &&
                    analysis.TicketUsernameMatch &&
                    analysis.TicketVersionMatch &&
                    analysis.TicketHashMatch &&
                    (!enforceHostAddressValidation || analysis.HostAddressMatch);

                if (!analysis.IsValid)
                {
                    analysis.IsMalicious =
                        !analysis.CookieDomainMatch ||
                        !analysis.CookiePathMatch ||
                        !analysis.CookieSecureMatch ||
                        /* !analysis.ExpirationMatch ||  */
                        !analysis.CookieNameMatch ||
                        !analysis.TicketPersistenceMatch ||
                        !analysis.TicketIssueDateMatch ||
                        !analysis.TicketUsernameMatch ||
                        !analysis.TicketVersionMatch ||
                        !analysis.TicketHashMatch ||
                        (enforceHostAddressValidation && !analysis.HostAddressMatch);
                }
            }
            else
            {
                analysis.IsValid = false;
                analysis.IsMalicious = false;
            }
            return analysis;
        }

        /// <summary>
        /// Retrieve and analyze the UserAuthenticationTicket
        /// </summary>
        /// <param name="contextInformation">Context information derived from the current request</param>
        /// <param name="cookieAnalysis">The result of the FormsAuthenticationCookie analysis</param>
        /// <param name="ticketAnalysis">The result of the FormsAuthenticationTicket analysis</param>
        /// <param name="enforceHostAddressValidation">Indicates whether to enforce that the ticket was provided from the same IP address for which it created</param>
        /// <returns>A UserAuthenticationTicketAnalysis object containing the results of the analysis</returns>
        public static UserAuthenticationTicketAnalysis AnalyzeServerAuthenticationTicket(ContextInformation contextInformation, FormsAuthenticationCookieAnalysis cookieAnalysis, FormsAuthenticationTicketAnalysis ticketAnalysis, bool enforceHostAddressValidation)
        {
            UserAuthenticationTicket serverAuthTicket = ticketAnalysis.GetServerAuthenticationTicket();
            return AnalyzeServerAuthenticationTicket(contextInformation, cookieAnalysis, ticketAnalysis, serverAuthTicket, enforceHostAddressValidation);
        }

        /// <summary>
        /// Performs a comparison of analyses taken a different points in the request processing pipeline
        /// </summary>
        /// <param name="before">The prior analysis</param>
        /// <param name="after">The current analysis</param>
        /// <returns>A conclusion derived from the analysis change</returns>
        public static ComparisonResult Compare(FormsAuthenticationAnalyzer before, FormsAuthenticationAnalyzer after)
        {
            if (before.RequestIsMalicious || after.RequestIsMalicious)
            {
                return ComparisonResult.MaliciousRequest;
            }
            if (before.RequestIsAuthenticated && after.RequestIsAuthenticated)
            {
                return ComparisonResult.AuthenticatedRequest;
            }
            if (before.RequestIsAuthenticated && !after.RequestIsAuthenticated)
            {
                return ComparisonResult.LogoutRequest;
            }
            if (!before.RequestIsAuthenticated && !after.RequestIsAuthenticated && before.FormsAuthenticationCookieResult.IsExpired)
            {
                return ComparisonResult.LogoutRequest;
            }
            if (!before.RequestIsAuthenticated && after.RequestIsAuthenticated)
            {
                return ComparisonResult.LoginRequest;
            }
            return ComparisonResult.UnauthenticatedRequest;
        }
    }
}