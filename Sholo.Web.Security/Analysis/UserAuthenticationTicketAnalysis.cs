using System;
using Sholo.Web.Security.Ticket;

namespace Sholo.Web.Security.Analysis
{
    /// <summary>
    /// Analysis result of the UserAuthenticationTicket validity & security
    /// </summary>
    [Serializable]
    public sealed class UserAuthenticationTicketAnalysis
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
}