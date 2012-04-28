<%@ Page Language="C#" MasterPageFile="Demo.master" CodeFile="Login.aspx.cs" Inherits="Login" %>
<asp:Content runat="server" ID="Body" ContentPlaceHolderID="Body">
    <asp:LoginView runat="server">
        <LoggedInTemplate>
            <p>
                <strong>You are not authorized to access that page.</strong>
            </p>
            <p>
                The UrlAuthorizationModule has restricted your access to the page you requested based 
                on the username contained in your FormsAuthenticationTicket and the configuration
                defined in web.config's configuration/location/system.web/authorization blocks.
            </p>
        </LoggedInTemplate>
        <AnonymousTemplate>
            <asp:Login ID="Login1" runat="server" />
        </AnonymousTemplate>
    </asp:LoginView>
</asp:Content>