using System;
using System.Web;
using System.Web.Security;
using Sholo.Web.Security.Authentication.User;

namespace Sholo.Web.Security.Analysis
{
    [Serializable]
    public sealed class RequestAnalysis
    {
        internal RequestAnalysis(ContextInformation context, FormsAuthenticationCookieAnalysis formsAuthenticationCookieResult, FormsAuthenticationTicketAnalysis formsAuthenticationTicketResult, UserAuthenticationTicketAnalysis userAuthenticationTicketResult)
        {
            Context = context;
            FormsAuthenticationCookieResult = formsAuthenticationCookieResult;
            FormsAuthenticationTicketResult = formsAuthenticationTicketResult;
            UserAuthenticationTicketResult = userAuthenticationTicketResult;
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
    }
}
