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
using System.Diagnostics;
using System.Security.Principal;
using System.Threading;
using System.Web;
using System.Web.Security;
using Sholo.Web.Security.Ticket;

namespace Sholo.Web.Security
{
    /// <summary>
    /// Utility class to analyze the state of FormsAuthenticationTickets and FormsAuthenticationCookies
    /// </summary>
    [Serializable]
    public class FormsAuthenticationAnalyzer
    {
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
        public ServerAuthenticationTicketAnalysis ServerAuthenticationTicketResult { get; private set; }

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
            if (EnhancedSecurity.MaintainServerTicketStore)
            {
                FormsAuthenticationTicketResult = AnalyzeFormsAuthenticationTicket(FormsAuthenticationCookieResult, true, isEndRequest);
                ServerAuthenticationTicketResult = AnalyzeServerAuthenticationTicket(Context, FormsAuthenticationCookieResult, FormsAuthenticationTicketResult, EnhancedSecurity.EnforceClientHostAddressValidation);
            }
            else
            {
                FormsAuthenticationTicketResult = AnalyzeFormsAuthenticationTicket(FormsAuthenticationCookieResult, false, isEndRequest);
                ServerAuthenticationTicketResult = new ServerAuthenticationTicketAnalysis();
            }
        }

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
                return ServerAuthenticationTicketResult.UserAuthenticationTicket;
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
                        (EnhancedSecurity.MaintainServerTicketStore && ServerAuthenticationTicketResult.IsValid)
                    || !EnhancedSecurity.MaintainServerTicketStore
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
                    || (EnhancedSecurity.MaintainServerTicketStore && ServerAuthenticationTicketResult.IsMalicious);
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
                    if (ticket.UserData != null && ticket.UserData.Length == EnhancedSecurity.HashAlgorithmStringLength + EnhancedSecurity.GuidStringLength + 1 && ticket.UserData[EnhancedSecurity.HashAlgorithmStringLength] == ';')
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
                                string actualHash = EnhancedSecurity.CalculateFormsAuthTicketHash(ticket);
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
                        UserAuthenticationTicket serverAuthenticationTicket = EnhancedSecurity.UserAuthenticationTicketStore.GetTicket(guid);
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
        /// <returns>A ServerAuthenticationTicketAnalysis object containing the results of the analysis</returns>
        public static ServerAuthenticationTicketAnalysis AnalyzeServerAuthenticationTicket(ContextInformation contextInformation, FormsAuthenticationCookieAnalysis cookieAnalysis, FormsAuthenticationTicketAnalysis ticketAnalysis, UserAuthenticationTicket userAuthenticationTicket, bool enforceHostAddressValidation)
        {
            ServerAuthenticationTicketAnalysis analysis = new ServerAuthenticationTicketAnalysis();
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
        /// <returns>A ServerAuthenticationTicketAnalysis object containing the results of the analysis</returns>
        public static ServerAuthenticationTicketAnalysis AnalyzeServerAuthenticationTicket(ContextInformation contextInformation, FormsAuthenticationCookieAnalysis cookieAnalysis, FormsAuthenticationTicketAnalysis ticketAnalysis, bool enforceHostAddressValidation)
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

        /// <summary>
        /// Context information derived from the current request
        /// </summary>
        [Serializable]
        public sealed class ContextInformation
        {
            /// <summary>
            /// ContextInformation constructor
            /// </summary>
            public ContextInformation()
            {
                HttpContext context = HttpContext.Current;
                HttpRequest request = context.Request;
                IPrincipal contextUser = context.User;
                IIdentity contextIdentity = (contextUser != null ? contextUser.Identity : null);
                IPrincipal threadUser = Thread.CurrentPrincipal;
                IIdentity threadIdentity = (threadUser != null ? threadUser.Identity : null);

                HostAddress = request.UserHostAddress;
                UserAgent = request.UserAgent;

                bool userIdentityIsAuthenticated = (contextIdentity != null && contextIdentity.IsAuthenticated);
                string userIdentityName = (contextIdentity != null ? contextIdentity.Name : null);
                bool threadCurrentPrincipalIdentityIsAuthenticated = (threadIdentity != null && threadIdentity.IsAuthenticated);
                string threadCurrentPrincipalIdentityName = (threadIdentity != null ? threadIdentity.Name : null);

                Debug.Assert(threadCurrentPrincipalIdentityIsAuthenticated == userIdentityIsAuthenticated);
                Debug.Assert((string.IsNullOrEmpty(userIdentityName) && string.IsNullOrEmpty(threadCurrentPrincipalIdentityName)) || userIdentityName == threadCurrentPrincipalIdentityName);

                IsAuthenticated = userIdentityIsAuthenticated;
                UserName = userIdentityName;
            }

            /// <summary>
            /// The User-Agent passed from the client
            /// </summary>
            public string UserAgent { get; set; }

            /// <summary>
            /// The host address of the client
            /// </summary>
            public string HostAddress { get; internal set; }
            
            /// <summary>
            /// Indicates whether or not the current request is authenticated
            /// </summary>
            public bool IsAuthenticated { get; internal set; }
            
            /// <summary>
            /// The username associated with the current request
            /// </summary>
            public string UserName { get; internal set; }
        }

        /// <summary>
        /// Analysis results of the FormsAuthenticationCookie validity & security
        /// </summary>
        [Serializable]
        public sealed class FormsAuthenticationCookieAnalysis
        {
            private FormsAuthenticationTicket _formsAuthenticationTicket;

            /// <summary>
            /// The FormsAuthenticationCookie to validate
            /// </summary>
            public HttpCookie FormsAuthenticationCookie { get; internal set; }

            /// <summary>
            /// Inidicates whether or not a FormsAuthenticationCookie was present in the current request
            /// </summary>
            public bool CookieExists { get; internal set; }
            
            /// <summary>
            /// Indicates whether the FormsAuthenticationCookie is valid
            /// </summary>
            public bool IsValid { get; internal set; }
            
            /// <summary>
            /// Indicates whether the FormsAuthenticationCookie is malicious
            /// </summary>
            public bool IsMalicious { get; internal set; }

            /// <summary>
            /// Indicates whether the expected FormsAuthenticationCookie cookie is an actual FormsAuthenticationCookie
            /// </summary>
            public bool IsCookieFormsAuthCookie { get; internal set; }
            
            /// <summary>
            /// Indicates whether the cookie domain is valid & matches the configured value
            /// </summary>
            public bool IsDomainValid { get; internal set; }
            
            /// <summary>
            /// Indicates whether the FormsAuthenticationCookie is expired
            /// </summary>
            public bool IsExpired { get; internal set; }
            
            /// <summary>
            /// Inidicates whether the CookiePath in the FormsAuthenticationCookie is valid & matches the configured value
            /// </summary>
            public bool IsPathValid { get; internal set; }
            
            /// <summary>
            /// Indicates whether the Secure property of the FormsAuthenticationCookie is valid & matches the configured value
            /// </summary>
            public bool IsSecureValid { get; internal set; }
            
            /// <summary>
            /// Indicates whether the cookie has a value
            /// </summary>
            public bool HasValue { get; internal set; }
            
            /// <summary>
            /// Indicates whether the cookie decrypts successfully
            /// </summary>
            public bool ValueDecrypts { get; internal set; }

            /// <summary>
            /// Retrieves the FormsAuthenticationTicket contained within the FormsAuthenticationCookie
            /// </summary>
            /// <returns>The FormsAuthenticationTicket contained within the FormsAuthenticationCookie</returns>
            public FormsAuthenticationTicket GetFormsAuthenticationTicket()
            {
                return _formsAuthenticationTicket;
            }

            internal void SetFormsAuthenticationTicket(FormsAuthenticationTicket ticket)
            {
                _formsAuthenticationTicket = ticket;
            }
        }

        /// <summary>
        /// Analysis results of the FormsAuthenticationTicket validity & security
        /// </summary>
        [Serializable]
        public sealed class FormsAuthenticationTicketAnalysis
        {
            private UserAuthenticationTicket _userAuthenticationTicket;

            /// <summary>
            /// The FormsAuthenticationTicket to validate
            /// </summary>
            public FormsAuthenticationTicket FormsAuthenticationTicket { get; internal set; }

            /// <summary>
            /// Indicates whether the FormsAuthenticationTicket exists
            /// </summary>
            public bool TicketExists { get; internal set; }
            
            /// <summary>
            /// Indicates whether or not the FormsAuthenticationTicket is valid
            /// </summary>
            public bool IsValid { get; internal set; }
            
            /// <summary>
            /// Indicates whether or not the FormsAuthenticationTicket is malicious
            /// </summary>
            public bool IsMalicious { get; internal set; }

            /// <summary>
            /// The ServerKey embedded in the UserData of the FormsAuthenticationTicket
            /// </summary>
            public string ServerKey { get; internal set; }
            
            /// <summary>
            /// The Ticket hash embedded in the UserData of the FormsAuthenticationTicket
            /// </summary>
            public string TicketHash { get; internal set; }

            /// <summary>
            /// Indicates whether the CookiePath contained in the FormsAuthenticationTicket matches the CookiePath contained in the FormsAuthenticationCookie
            /// </summary>
            public bool CookiePathMatches { get; internal set; }
            
            /// <summary>
            /// Indicates whether the FormsAuthenticationTicket is expired
            /// </summary>
            public bool IsExpired { get; internal set; }
            
            /// <summary>
            /// Indicates whether the FormsAuthenticationTicket persistence is valid
            /// </summary>
            public bool IsPersistenceValid { get; internal set; }
            
            /// <summary>
            /// Indicates whether the FormsAuthenticationTicket IssueDate is valid
            /// </summary>
            public bool IsIssueDateValid { get; internal set; }
            
            /// <summary>
            /// Indicates whether the FormsAuthenticationTicket Name is valid
            /// </summary>
            public bool IsNameValid { get; internal set; }
            
            /// <summary>
            /// Indicates whether the FormsAuthenticationTicket has UserData
            /// </summary>
            public bool HasUserData { get; internal set; }
            
            /// <summary>
            /// Indicates whether the FormsAuthenticationTicket UserData contains a hash
            /// </summary>
            public bool UserDataContainsHash { get; set; }
            
            /// <summary>
            /// Indicates whether the FormsAuthenticationTicket UserData hash is valid
            /// </summary>
            public bool IsUserDataHashValid { get; set; }
            
            /// <summary>
            /// Indicates whether the FormsAuthenticationTicket UserData contains a UserAuthenticationTicket key
            /// </summary>
            public bool UserDataContainsServerAuthenticationTicketKey { get; internal set; }
            
            /// <summary>
            /// Indicates whether the FormsAuthenticationTicket UserData UserAuthenticationTicket exists in the ticket store
            /// </summary>
            public bool UserDataServerAuthenticationTicketKeyFound { get; internal set; }
            
            /// <summary>
            /// Indicates whether the FormsAuthenticationTicket Version is valid
            /// </summary>
            public bool IsVersionValid { get; internal set; }

            /// <summary>
            /// Retrieves the UserAuthenticationTicket referenced by the FormsAuthenticationTicket
            /// </summary>
            /// <returns>The UserAuthenticationTicket referenced by the FormsAuthenticationTicket</returns>
            public UserAuthenticationTicket GetServerAuthenticationTicket()
            {
                return _userAuthenticationTicket;
            }

            internal void SetServerAuthenticationTicket(UserAuthenticationTicket userAuthenticationTicket)
            {
                _userAuthenticationTicket = userAuthenticationTicket;
            }
        }

        /// <summary>
        /// Analysis result of the UserAuthenticationTicket validity & security
        /// </summary>
        [Serializable]
        public sealed class ServerAuthenticationTicketAnalysis
        {
            /// <summary>
            /// The UserAuthenticationTicket to validate
            /// </summary>
            public UserAuthenticationTicket UserAuthenticationTicket { get; internal set; }

            /// <summary>
            /// Indicates whether the UserAuthenticationTicket exists
            /// </summary>
            public bool TicketExists { get; internal set; }
            
            /// <summary>
            /// Indicates whether the UserAuthenticationTicket is valid
            /// </summary>
            public bool IsValid { get; internal set; }
            
            /// <summary>
            /// Indicates whether the UserAuthenticationTicket is malicious
            /// </summary>
            public bool IsMalicious { get; internal set; }

            /// <summary>
            /// Indicates whether the FormsAuthenticationCookie Domain matches the UserAuthenticationTicket Domain
            /// </summary>
            public bool CookieDomainMatch { get; internal set; }
            
            /// <summary>
            /// Indicates whether the FormsAuthenticationCookie Path matches the UserAuthenticationTicket Path
            /// </summary>
            public bool CookiePathMatch { get; internal set; }
            
            /// <summary>
            /// Indicates whether the FormsAuthenticationCookie Secure property matches the UserAuthenticationTicket Secure property
            /// </summary>
            public bool CookieSecureMatch { get; internal set; }
                        
            /// <summary>
            /// Indicates whether the FormsAuthenticationCookie Name matches the UserAuthenticationTicket Name
            /// </summary>
            public bool CookieNameMatch { get; internal set; }
            
            /// <summary>
            /// Indicates whether the FormsAuthenticationTicket IsPersistent property matches the UserAuthenticationTicket IsPersistent property
            /// </summary>
            public bool TicketPersistenceMatch { get; internal set; }
            
            /// <summary>
            /// Indicates whether the FormsAuthenticationTicket IssueDate matches the UserAuthenticationTicket IssueDate
            /// </summary>
            public bool TicketIssueDateMatch { get; internal set; }
            
            /// <summary>
            /// Indicates whether the FormsAuthenticationTicket Name matches the UserAuthenticationTicket UserName
            /// </summary>
            public bool TicketUsernameMatch { get; internal set; }
            
            /// <summary>
            /// Indicates whether the FormsAuthenticationTicket Version matches the UserAuthenticationTicket Version
            /// </summary>
            public bool TicketVersionMatch { get; internal set; }
            
            /// <summary>
            /// Indicates whether the FormsAuthenticationTicket hash matches the UserAuthenticationTicket hash
            /// </summary>
            public bool TicketHashMatch { get; internal set; }
            
            /// <summary>
            /// Indicates whether the current request's host address matches the UserAuthenticationTicket's host address
            /// </summary>
            public bool HostAddressMatch { get; internal set; }
        }

        /// <summary>
        /// The result of a comparison of two different analyses taken a different points in the request processing pipeline
        /// </summary>
        public enum ComparisonResult
        {
            /// <summary>
            /// The current request is authenticated
            /// </summary>
            AuthenticatedRequest,
            
            /// <summary>
            /// The current request is anonymous
            /// </summary>
            UnauthenticatedRequest,
            
            /// <summary>
            /// The current request resulted in the creation of a FormsAuthenticationTicket
            /// </summary>
            LoginRequest,
            
            /// <summary>
            /// The current request resulted in the removal of a FormsAuthenticationTicket
            /// </summary>
            LogoutRequest,
            
            /// <summary>
            /// The current request is malicious
            /// </summary>
            MaliciousRequest
        }
    }
}