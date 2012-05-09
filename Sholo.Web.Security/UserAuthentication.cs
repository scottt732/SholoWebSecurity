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
using System.Configuration;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Threading;
using System.Web;
using System.Web.Configuration;
using System.Web.Security;
using Sholo.Web.Security.Configuration;
using Sholo.Web.Security.Provider;
using Sholo.Web.Security.State;

namespace Sholo.Web.Security
{
    /// <summary>
    /// UserAuthentication exposes a public API for use in working with 
    /// stateful Forms Authentication in the .NET Framework.
    /// </summary>
    public sealed class UserAuthentication
    {
        #region Fields
        ///<summary>
        /// The expected string length of a hash
        ///</summary>
        public static readonly int HashAlgorithmStringLength = 128;

        ///<summary>
        /// The expected number of bytes of a hash
        ///</summary>
        public static readonly int HashAlgorithmByteLength = 64;

        ///<summary>
        /// The expected string length of a GUID
        ///</summary>
        public static readonly int GuidStringLength = 36;

        // Thread-safe initialization
        private static readonly object LockObject;
        private static bool _initialized;

        // System.Web/Authentication and System.Web/Authentication/Forms static classes
        internal static AuthenticationSection AuthenticationConfig;
        internal static UserAuthenticationConfiguration UserAuthenticationConfig;

        private static SHA512Managed _hashAlgorithm;

        private static TimeSpan _formsTimeout;

        private static bool _enabled;
        private static bool _enforceClientHostAddressValidation;
        private static bool _enforceUserAgentValidation;
        private static string _hashSalt;
        private static string _stateProvider;
        private static IUserAuthenticationTicketStore _userAuthenticationTicketStore;

        #endregion

        #region Methods
        /// <summary>
        /// Static constructor
        /// </summary>
        static UserAuthentication()
        {
            LockObject = new object();
        }

        /// <summary>
        /// Initializes configuration-related properties and validates configuration.
        /// </summary>        
        public static void Initialize()
        {
            if (!_initialized)
            {
                lock (LockObject)
                {
                    if (!_initialized)
                    {
                        FormsAuthentication.Initialize();
                        AuthenticationConfig = (AuthenticationSection)WebConfigurationManager.GetSection("system.web/authentication");
                        UserAuthenticationConfig = UserAuthenticationConfiguration.GetConfig();

                        if (UserAuthenticationConfig == null)
                        {
                            _enabled = false;
                        }
                        else
                        {
                            _enabled = UserAuthenticationConfig.Enabled;
                        }

                        _hashAlgorithm = new SHA512Managed();

                        if (_enabled)
                        {
                            if (AuthenticationConfig == null)
                            {
                                throw new ConfigurationErrorsException("The UserAuthenticationModule requires Forms authentication to be enabled in web.config.");
                            }

                            _formsTimeout = AuthenticationConfig.Forms.Timeout;

                            if (AuthenticationConfig.Mode != AuthenticationMode.Forms)
                            {
                                throw new ConfigurationErrorsException("The UserAuthenticationModule requires Forms authentication to be enabled in web.config.");
                            }

                            if (FormsAuthentication.CookieMode != HttpCookieMode.UseCookies)
                            {
                                throw new ConfigurationErrorsException("The UserAuthenticationModule requires Forms Authentication to use cookies (cookieless='UseCookies').");
                            }

                            if (UserAuthenticationConfig.StateProvider == null)
                            {
                                // TODO: Add exception text
                                throw new ConfigurationErrorsException("TODO");
                            }

                            _stateProvider = UserAuthenticationConfig.StateProvider;
                            var providerSettings = UserAuthenticationConfig.Providers[_stateProvider];

                            if (providerSettings == null)
                            {
                                // TODO: Add exception text
                                throw new ConfigurationErrorsException("TODO");
                            }

                            _userAuthenticationTicketStore = (IUserAuthenticationTicketStore) ProvidersHelper.InstantiateProvider(providerSettings, typeof (UserAuthenticationTicketProvider));

                            _enforceClientHostAddressValidation = UserAuthenticationConfig.EnforceClientHostAddressValidation;
                            _enforceUserAgentValidation = UserAuthenticationConfig.EnforceUserAgentValidation;

                            /* TODO: Implement/fix sliding UserAuthenticationTicketStore expiration */
                            _hashSalt = UserAuthenticationConfig.HashSalt;
                        }
                        else
                        {
                            if (AuthenticationConfig != null && AuthenticationConfig.Mode == AuthenticationMode.Forms)
                            {
                                _formsTimeout = AuthenticationConfig.Forms.Timeout;
                            }

                            _enforceClientHostAddressValidation = false;
                            _enforceUserAgentValidation = false;
                        }

                        _initialized = true;
                    }
                }

                if (_enabled)
                {
                    if (UserAuthenticationTicketStore != null) UserAuthenticationTicketStore.Initialize();
                }
            }
        }
        /// <summary>
        /// Calculates the hash of the FormsAuthenticationTicket's properties 
        /// concatenated together with the salt.  This is used as a first line of 
        /// defense against ticket tampering to potentially avoid an unnecessary read
        /// from the UserAuthenticationTicketStore.
        /// </summary>
        /// <param name="formsAuthenticationTicket">the formsAuthenticationTicket to 
        /// compute the hash of</param>
        /// <returns>the hash of ticket's properties</returns>
        public static string CalculateFormsAuthTicketHash(FormsAuthenticationTicket formsAuthenticationTicket)
        {
            if (formsAuthenticationTicket == null)
            {
                throw new ArgumentNullException("formsAuthenticationTicket", "The formsAuthenticationTicket parameter is required.");
            }

            Initialize();

            string input = string.Format(
                "||{0}|{1}|{2}|{3}|{4}|{5}|{6}||",
                formsAuthenticationTicket.CookiePath,
                formsAuthenticationTicket.Expiration,
                formsAuthenticationTicket.IsPersistent,
                formsAuthenticationTicket.IssueDate,
                formsAuthenticationTicket.Name,
                formsAuthenticationTicket.Version,
                HashSalt
            );

            byte[] inputBytes = Encoding.UTF32.GetBytes(input);
            byte[] hashBytes = HashAlgorithm.ComputeHash(inputBytes);

            StringBuilder sb = new StringBuilder();
            if (hashBytes.Length != HashAlgorithmByteLength)
            {
                throw new InvalidOperationException("Unable to compute hash of formsAuthenticationTicket.");
            }

            for (int i = 0; i < hashBytes.Length; i++)
            {
                sb.Append(hashBytes[i].ToString("x2"));
            }

            if (sb.Length != HashAlgorithmStringLength)
            {
                throw new InvalidOperationException("Unable to compute hash of formsAuthenticationTicket");
            }

            string hash = sb.ToString();
            return hash;
        }

        /// <summary>
        /// Calculates the hash of the formsAuthenticationTicket and compares it 
        /// to the expected hash
        /// </summary>
        /// <param name="formsAuthenticationTicket">The formsAuthenticationTicket to hash</param>
        /// <param name="expectedHash">The expected hash value</param>
        /// <returns>A boolean indicating whether the expectedHash is correct</returns>
        public static bool ValidateFormsAuthTicketHash(FormsAuthenticationTicket formsAuthenticationTicket, string expectedHash)
        {
            if (formsAuthenticationTicket == null)
            {
                throw new ArgumentNullException("formsAuthenticationTicket", "formsAuthenticationTicket parameter cannot be null.");
            }

            if (expectedHash == null)
            {
                throw new ArgumentNullException("expectedHash", "expectedHash parameter cannot be null or empty.");
            }
            if (string.IsNullOrEmpty(expectedHash))
            {
                throw new ArgumentException("expectedHash parameter cannot be null or empty.", "expectedHash");
            }

            string calculatedHash = CalculateFormsAuthTicketHash(formsAuthenticationTicket);
            return (string.Compare(expectedHash, calculatedHash, StringComparison.Ordinal) == 0);
        }

        /// <summary>
        /// Sends a blank and expired FormsAuthentication cookie to the 
        /// client response.  This effectively removes the FormsAuthentication
        /// cookie and revokes the FormsAuthenticationTicket.  It also removes
        /// the cookie from the current Request object, preventing subsequent 
        /// code from being able to access it during the execution of the 
        /// current request.  And just for good measure, it also replaces any
        /// existing principal in the current request pipeline with an anonymous 
        /// one.
        /// </summary>
        public static void ClearAuthCookie()
        {
            Initialize();
            HttpContext current = HttpContext.Current;

            // Don't let anything see the incoming cookie 
            current.Request.Cookies.Remove(FormsAuthentication.FormsCookieName);

            GenericPrincipal anon = new GenericPrincipal(new GenericIdentity(string.Empty), null);
            Thread.CurrentPrincipal = anon;
            current.User = anon;

            // Remove the cookie from the response collection (by adding an expired/empty version).
            HttpCookie cookie = new HttpCookie(FormsAuthentication.FormsCookieName)
            {
                Expires = DateTime.Now.AddMonths(-1),
                Domain = FormsAuthentication.CookieDomain,
                Path = FormsAuthentication.FormsCookiePath
            };

            current.Response.Cookies.Add(cookie);
        }

        /// <summary>
        /// Encrypts a FormsAuthenticationTicket in an HttpCookie (using GetAuthCookie) 
        /// and includes it in the current Request's Cookies collection and/or the 
        /// Response's outbound Cookies collection.
        /// </summary>
        /// <param name="clientTicket">The FormsAuthenticationTicket to encode</param>
        /// <param name="overwriteRequestCookie">Whether or not to replace the cookie in
        /// the current Request's Cookies collection.  This will trick later executing 
        /// code on the current HTTP request into processing the updated cookie</param>
        /// <param name="writeResponseCookie">Whether or not to write the cookie to the 
        /// browser via the Response's Cookies collection.</param>
        public static void SetAuthCookie(FormsAuthenticationTicket clientTicket, bool overwriteRequestCookie, bool writeResponseCookie)
        {
            Initialize();
            HttpContext current = HttpContext.Current;

            if (overwriteRequestCookie)
            {
                current.Request.Cookies.Remove(FormsAuthentication.FormsCookieName);
                current.Request.Cookies.Add(GetAuthCookie(clientTicket));
            }

            if (writeResponseCookie)
            {
                if (!current.Request.IsSecureConnection && FormsAuthentication.RequireSSL)
                {
                    throw new HttpException("Connection not secure while creating secure cookie");
                }
                current.Response.Cookies.Add(GetAuthCookie(clientTicket));
            }
        }

        /// <summary>
        /// Creates an HttpCookie containing an encrypted FormsAuthenticationTicket.
        /// The ticket must contain an hash and key into the UserAuthenticationTicketStore.
        /// </summary>
        /// <param name="ticket">The FormsAuthenticationTicket to encode</param>
        /// <returns>An HttpCookie containing the encrypted FormsAuthenticationTicket</returns>
        public static HttpCookie GetAuthCookie(FormsAuthenticationTicket ticket)
        {
            Initialize();

            /*
            if (string.IsNullOrEmpty(ticket.UserData))
            {
                throw new InvalidOperationException("The ticket's UserData property is not set properly.");
            }
            */

            string str = FormsAuthentication.Encrypt(ticket);

            if (String.IsNullOrEmpty(str))
            {
                throw new HttpException("Unable to encrypt cookie ticket");
            }

            HttpCookie cookie = new HttpCookie(FormsAuthentication.FormsCookieName, str)
            {
                HttpOnly = true,
                Path = FormsAuthentication.FormsCookiePath,
                Secure = FormsAuthentication.RequireSSL
            };

            // Per http://support.microsoft.com/kb/900111 :
            // In ASP.NET 2.0, forms authentication cookies are HttpOnly cookies. 
            // HttpOnly cookies cannot be accessed through client script. This 
            // functionality helps reduce the chances of replay attacks.

            if (FormsAuthentication.CookieDomain != null)
            {
                cookie.Domain = FormsAuthentication.CookieDomain;
            }

            if (ticket.IsPersistent)
            {
                cookie.Expires = ticket.Expiration;
            }

            return cookie;
        }

        /// <summary>
        /// Creates a FormsAuthenticationTicket for storage on the client.
        /// The UserData field contains the server key, which can be 
        /// used by the server-side UserAuthenticationTicketStore to retrieve validation data 
        /// and additional details about the ticket (e.g. IP address)
        /// </summary>
        /// <param name="username">User associated with the ticket</param>
        /// <param name="cookiePath">Relative path on server in which cookie is valid</param>
        /// <param name="serverKey">UserAuthenticationTicketStore key</param>
        /// <param name="validFromDate">Ticket valid from date</param>
        /// <param name="validUntilDate">Ticket valid to date</param>
        /// <param name="persistent">Ticket can persist across browser sessions</param>
        /// <returns>Instance of a FormsAuthenticationTicket</returns>
        public static FormsAuthenticationTicket CreateFormsAuthTicket(string username, string cookiePath, string serverKey, DateTime? validFromDate, DateTime? validUntilDate, bool persistent)
        {
            if (username == null)
            {
                throw new ArgumentNullException("username", "username parameter cannot be null or empty.");
            }
            if (string.IsNullOrEmpty(username))
            {
                throw new ArgumentException("username parameter cannot be null or empty.", "username");
            }

            /*
            if (serverKey == null)
            {
                throw new ArgumentNullException("serverKey", "serverKey parameter cannot be null or empty.");
            }
            else if (string.IsNullOrEmpty(serverKey))
            {
                throw new ArgumentException("serverKey parameter cannot be null or empty.", "serverKey");
            }                
            */

            Initialize();

            DateTime fromDate = validFromDate.HasValue ? validFromDate.Value : DateTime.Now;
            DateTime toDate = validUntilDate.HasValue ? validUntilDate.Value : fromDate.Add(FormsTimeout);

            FormsAuthenticationTicket ticket = new FormsAuthenticationTicket(
                2,
                username,
                fromDate,
                toDate,
                persistent,
                serverKey ?? string.Empty,
                cookiePath ?? FormsAuthentication.FormsCookiePath
            );

            return ticket;
        }
        #endregion

        #region Properties
        /// <summary>
        /// Indicates whether or not the UserAuthenticationModule is enabled.
        /// </summary>
        public static bool Enabled
        {
            get
            {
                Initialize();
                return _enabled;
            }
        }

        /// <summary>
        /// The ticket store containing a record of tickets issued by the server. 
        /// </summary>
        public static string StateProvider
        {
            get
            {
                Initialize();
                return _stateProvider;
            }
        }

        /// <summary>
        /// An instance of the provider specified in the TicketStoreProvider property.
        /// The UserAuthenticationTicketStore allows access to validation-related information about outstanding 
        /// FormsAuthenticationCookies and FormsAuthenticationTickets along with the host 
        /// address of the client that initially requested the ticket.
        /// </summary>
        public static IUserAuthenticationTicketStore UserAuthenticationTicketStore
        {
            get
            {
                Initialize();
                return _userAuthenticationTicketStore;
            }
        }

        /// <summary>
        /// An instance of a Hash algorithm that is used to calculate the checksum of a 
        /// FormsAuthenticationTicket's properties.
        /// </summary>
        public static SHA512Managed HashAlgorithm
        {
            get
            {
                Initialize();
                return _hashAlgorithm;
            }
        }

        /// <summary>
        /// The Forms Timeout property set in system.web/authentication/forms
        /// </summary>
        public static TimeSpan FormsTimeout
        {
            get
            {
                Initialize();
                return _formsTimeout;
            }
        }

        /// <summary>
        /// Whether or not to enforce client host address validation.  With this option enabled, a FormsAuthenticationTicket
        /// will only validate received from the IP address on which it was generated.  This prevents ticket stealing, but
        /// will result in a user being logged out in the event that their IP address changes.
        /// </summary>
        public static bool EnforceClientHostAddressValidation
        {
            get
            {
                Initialize();
                return _enforceClientHostAddressValidation;
            }
        }

        /// <summary>
        /// Whether or not to enforce browser User-Agent validation.  With this option enabled, a FormsAuthenticationTicket
        /// will only validate if received a browser with the same User-Agent header as the browser used to create the ticket.
        /// If the User-Agent header was omitted when the ticket was issued, it must never re-appear or else the user will be
        /// logged out automatically.
        /// </summary>
        public static bool EnforceUserAgentValidation
        {
            get
            {
                Initialize();
                return _enforceUserAgentValidation;
            }
        }

        /// <summary>
        /// The string to salt generated hashes with to prevent tampering.  Always set a unique hash salt and
        /// keep it safe
        /// </summary>
        public static string HashSalt
        {
            get
            {
                Initialize();
                return _hashSalt;
            }
        }
        #endregion
    }
}