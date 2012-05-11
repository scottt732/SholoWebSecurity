<%@ Page Language="C#" MasterPageFile="Demo.master" CodeFile="Login.aspx.cs" Inherits="Login" %>
<%--
Copyright 2010-2012, Scott Holodak, Alex Friedman

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
--%>
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