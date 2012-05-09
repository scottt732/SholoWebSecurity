namespace Sholo.Web.Security.Analysis
{
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