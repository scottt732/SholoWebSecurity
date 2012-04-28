using System;

namespace Sholo.Web.Security.Ticket
{
    ///<summary>
    /// A contract for a data object containing information about 
    /// FormsAuthenticationCookies, FormsAuthenticationTickets,
    /// and the IP address of the client that requested them.  This
    /// is used for the stateful validation of incoming requests.
    ///</summary>
    public interface IAuthenticationTicket
    {
        /// <summary>
        /// A GUID serving as the primary key in the UserAuthenticationTicketStore
        /// </summary>
        string Key { get; set; }

        /// <summary>
        /// The name of the FormsAuthenticationCookie
        /// </summary>
        string CookieName { get; set; }

        /// <summary>
        /// The domain on the FormsAuthenticationCookie
        /// </summary>
        string CookieDomain { get; set; }

        /// <summary>
        /// The path on the server for which the FormsAuthenticationCookie is applicable.
        /// </summary>
        string CookiePath { get; set; }

        /// <summary>
        /// Whether or not the FormsAuthenticationCookie requires HTTPS
        /// </summary>
        bool CookieSecure { get; set; }

        /// <summary>
        /// The expiration date of the FormsAuthenticationTicket
        /// </summary>
        DateTime TicketExpiration { get; set; }

        /// <summary>
        /// Whether or not the FormsAuthenticationTicket is allowed to 
        /// persist across browser sessions.
        /// </summary>
        bool TicketIsPersistent { get; set; }

        /// <summary>
        /// The date and time at which the FormsAuthenticationTicket was
        /// issued.
        /// </summary>
        DateTime TicketIssueDate { get; set; }

        /// <summary>
        /// The UserData field originally contained in the FormsAuthenticationTicket.
        /// Unlike the other properties which are copied here, the original UserData 
        /// contained in the FormsAuthenticationTicket is moved here to make room for 
        /// the hash of the FormsAuthenticationTicket's properties and and GUID
        /// corresponding to the Key in this data structure.
        /// </summary>
        string TicketUserData { get; set; }

        /// <summary>
        /// The FormsAuthenticationTicket version (always expected to be 2 for 
        /// ASP.NET 2.0-4.0)
        /// </summary>
        int TicketVersion { get; set; }

        /// <summary>
        /// The hash of the FormsAuthenticationTicket's properties concatenated
        /// with a salt string.
        /// </summary>
        string TicketHash { get; set; }

        /// <summary>
        /// Readonly property which indicates whether or not the ValidUntilDate is in
        /// the past (i.e., the ticket is expired).  IsExpired tickets should/will be 
        /// purged from the UserAuthenticationTicketStore during the RemoveExpiredTickets() call,
        /// during the BeginRequest event handler.
        /// </summary>
        bool TicketExpired
        {
            get;
        }
    }
}
