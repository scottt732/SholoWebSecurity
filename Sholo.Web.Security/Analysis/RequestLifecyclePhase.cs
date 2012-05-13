using System;
using System.Collections.Generic;
using System.Text;

namespace Sholo.Web.Security.Analysis
{
    public enum RequestLifecyclePhase
    {
        BeginRequest,
        AuthenticateRequest,
        PostAuthenticateRequest,
        AuthorizeRequest,
        PostAuthorizeRequest,
        ResolveRequestCache,
        PostResolveRequestCache,
        MapRequestHandler,
        PostMapRequestHandler,
        AcquireRequestState,
        PostAcquireRequestState,
        PreRequestHandlerExecute,
        ProcessRequest,
        ProcessRequestAsync,
        PostRequestHandlerExecute,
        ReleaseRequestState,
        PostReleaseRequestState,
        ResponseFiltering,
        UpdateRequestCache,
        PostUpdateRequestCache,
        LogRequest,
        PostLogRequest,
        EndRequest,
        PreSendRequestHeaders,
        PreSendRequestContent,
    }
}
