/*
 * Licensed to Jasig under one or more contributor license
 * agreements. See the NOTICE file distributed with this work
 * for additional information regarding copyright ownership.
 * Jasig licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file
 * except in compliance with the License. You may obtain a
 * copy of the License at:
 * 
 * http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on
 * an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

using System;
using System.Drawing;
using System.Text;
using System.Web;
using System.Web.Security;
using Sholo.Web.Security;
using Sholo.Web.Security.Analysis;
using Sholo.Web.Security.Authentication.User;

public partial class User_controls_CookieMonster : System.Web.UI.UserControl
{
    FormsAuthenticationAnalyzer preAnalyzer;
    FormsAuthenticationAnalyzer postAnalyzer;

    protected void Page_Load(object sender, EventArgs e)
    {
        preAnalyzer = Context.Items["preAnalyzer"] as FormsAuthenticationAnalyzer;
        postAnalyzer = new FormsAuthenticationAnalyzer(HttpContext.Current.Request.Cookies[FormsAuthentication.FormsCookieName], false);

        if (!Page.IsPostBack)
        {
            BindFields();
        }
        ValidateFields();
    }

    private void BindFields()
    {
        if (Context.Items["OriginalCookieValue"] != null)
        {
            CookieValueClient.Text = Wrap(postAnalyzer.FormsAuthenticationCookie.Value);
        }

        TicketUserDataClient.Text = postAnalyzer.FormsAuthenticationTicket != null ? postAnalyzer.FormsAuthenticationTicket.UserData ?? string.Empty : string.Empty;
            // Context.Items["ServerUserData"] != null ? Context.Items["ServerUserData"].ToString() : string.Empty;
        
        // string serverTicketKey = Context.Items["ServerTicketKey"] != null ? Context.Items["ServerTicketKey"].ToString() : null;

        RequestHostAddress.Text = preAnalyzer.Context.HostAddress;
        RequestIsAuthenticated.Checked = preAnalyzer.Context.IsAuthenticated;
        RequestUserName.Text = postAnalyzer.Context.UserName;

        if (preAnalyzer.FormsAuthenticationCookie != null)
        {
            CookieDomain.Text = preAnalyzer.FormsAuthenticationCookie.Domain;
            CookieExpires.Text = (preAnalyzer.FormsAuthenticationCookie.Expires.CompareTo(DateTime.MinValue) == 0 ? string.Empty : preAnalyzer.FormsAuthenticationCookie.Expires.ToString());
            CookieName.Text = preAnalyzer.FormsAuthenticationCookie.Name;
            CookiePath.Text = preAnalyzer.FormsAuthenticationCookie.Path;
            CookieSecure.Checked = preAnalyzer.FormsAuthenticationCookie.Secure;

            if (!string.IsNullOrEmpty(preAnalyzer.FormsAuthenticationCookie.Value))
            {
                CookieValueServer.Text = Wrap(preAnalyzer.FormsAuthenticationCookie.Value);
            }            
        }

        if (preAnalyzer.FormsAuthenticationTicket != null)
        {
            TicketCookiePath.Text = preAnalyzer.FormsAuthenticationTicket.CookiePath;
            TicketExpiration.Text = (preAnalyzer.FormsAuthenticationTicket.Expiration.CompareTo(DateTime.MinValue) == 0 ? string.Empty : preAnalyzer.FormsAuthenticationTicket.Expiration.ToString());
            TicketIsPersistent.Checked = preAnalyzer.FormsAuthenticationTicket.IsPersistent;
            TicketIssueDate.Text = (preAnalyzer.FormsAuthenticationTicket.IssueDate.CompareTo(DateTime.MinValue) == 0 ? string.Empty : preAnalyzer.FormsAuthenticationTicket.IssueDate.ToString());
            TicketName.Text = preAnalyzer.FormsAuthenticationTicket.Name;
            TicketUserDataServer.Text = preAnalyzer.FormsAuthenticationTicket.UserData;
            TicketVersion.Text = preAnalyzer.FormsAuthenticationTicket.Version.ToString();
        }

        Page.ClientScript.RegisterHiddenField("OriginalTicketKey", preAnalyzer.FormsAuthenticationTicketResult.ServerKey);

        if (preAnalyzer.UserAuthenticationTicket != null)
        {
            ServerKey.Text = preAnalyzer.UserAuthenticationTicket.Key;
            ServerUsername.Text = preAnalyzer.UserAuthenticationTicket.Username;
            ServerHostAddress.Text = preAnalyzer.UserAuthenticationTicket.HostAddress;
            ServerCookieName.Text = preAnalyzer.UserAuthenticationTicket.CookieName;
            ServerCookieDomain.Text = preAnalyzer.UserAuthenticationTicket.CookieDomain;
            ServerCookiePath.Text = preAnalyzer.UserAuthenticationTicket.CookiePath;
            ServerCookieSecure.Checked = preAnalyzer.UserAuthenticationTicket.CookieSecure;
            ServerTicketExpiration.Text = preAnalyzer.UserAuthenticationTicket.TicketExpiration.ToString();
            ServerTicketIsPersistent.Checked = preAnalyzer.UserAuthenticationTicket.TicketIsPersistent;
            ServerTicketIssueDate.Text = preAnalyzer.UserAuthenticationTicket.TicketIssueDate.ToString();
            ServerTicketUserData.Text = preAnalyzer.UserAuthenticationTicket.TicketUserData;
            ServerTicketVersion.Text = preAnalyzer.UserAuthenticationTicket.TicketVersion.ToString();
            ServerTicketHash.Text = preAnalyzer.UserAuthenticationTicket.TicketHash;
        }
    }

    private void ValidateFields()
    {        
        RequestHostAddressValid.BackColor = GetColor(preAnalyzer.UserAuthenticationTicketResult.HostAddressMatch);
        RequestUserNameValid.BackColor = GetColor(preAnalyzer.UserAuthenticationTicketResult.TicketUsernameMatch);

        CookieDomainValid.BackColor = GetColor(preAnalyzer.FormsAuthenticationCookieResult.IsDomainValid);
        CookieNameValid.BackColor = GetColor(preAnalyzer.FormsAuthenticationCookieResult.IsCookieFormsAuthCookie);
        CookieSecureValid.BackColor = GetColor(preAnalyzer.FormsAuthenticationCookieResult.IsSecureValid);
        CookieValueServerValid.BackColor = GetColor((preAnalyzer.FormsAuthenticationCookieResult.HasValue && preAnalyzer.FormsAuthenticationCookieResult.ValueDecrypts) || !preAnalyzer.FormsAuthenticationCookieResult.HasValue);

        TicketNameValid.BackColor = GetColor(preAnalyzer.FormsAuthenticationTicketResult.IsNameValid);
        TicketCookiePathValid.BackColor = GetColor(preAnalyzer.FormsAuthenticationTicketResult.CookiePathMatches);
        TicketIsPersistentValid.BackColor = GetColor(preAnalyzer.FormsAuthenticationTicketResult.IsPersistenceValid);
        TicketIssueDateValid.BackColor = GetColor(preAnalyzer.FormsAuthenticationTicketResult.IsIssueDateValid);
        TicketUserDataServerValid.BackColor = GetColor(preAnalyzer.FormsAuthenticationTicketResult.UserDataContainsHash && preAnalyzer.FormsAuthenticationTicketResult.IsUserDataHashValid && preAnalyzer.FormsAuthenticationTicketResult.UserDataContainsServerAuthenticationTicketKey);
        TicketVersionValid.BackColor = GetColor(preAnalyzer.FormsAuthenticationTicketResult.IsVersionValid);

        ServerHostAddressValid.BackColor = GetColor(preAnalyzer.UserAuthenticationTicketResult.HostAddressMatch);
        ServerUsernameValid.BackColor = GetColor(preAnalyzer.UserAuthenticationTicketResult.TicketUsernameMatch);
        ServerCookieDomainValid.BackColor = GetColor(preAnalyzer.UserAuthenticationTicketResult.CookieDomainMatch);
        ServerCookieNameValid.BackColor = GetColor(preAnalyzer.UserAuthenticationTicketResult.CookieNameMatch);
        ServerCookiePathValid.BackColor = GetColor(preAnalyzer.UserAuthenticationTicketResult.CookiePathMatch);
        ServerCookieSecureValid.BackColor = GetColor(preAnalyzer.UserAuthenticationTicketResult.CookieSecureMatch);
        ServerTicketIsPersistentValid.BackColor = GetColor(preAnalyzer.UserAuthenticationTicketResult.TicketPersistenceMatch);
        ServerTicketIssueDateValid.BackColor = GetColor(preAnalyzer.UserAuthenticationTicketResult.TicketIssueDateMatch);
        ServerKeyValid.BackColor = GetColor(preAnalyzer.UserAuthenticationTicketResult.TicketExists);
        ServerTicketHashValid.BackColor = GetColor(preAnalyzer.UserAuthenticationTicketResult.TicketHashMatch);
        ServerTicketVersionValid.BackColor = GetColor(preAnalyzer.UserAuthenticationTicketResult.TicketVersionMatch);

        StatusColor.BackColor = GetColor(
            preAnalyzer.FormsAuthenticationCookieResult.IsValid && preAnalyzer.FormsAuthenticationTicketResult.IsValid && preAnalyzer.UserAuthenticationTicketResult.IsValid,
            preAnalyzer.FormsAuthenticationCookieResult.IsMalicious || preAnalyzer.FormsAuthenticationTicketResult.IsMalicious || preAnalyzer.UserAuthenticationTicketResult.IsMalicious
        );

        CurrentRequestValid.BackColor = GetColor(
            preAnalyzer.FormsAuthenticationCookieResult.IsValid && preAnalyzer.FormsAuthenticationTicketResult.IsValid && preAnalyzer.UserAuthenticationTicketResult.IsValid,
            preAnalyzer.FormsAuthenticationCookieResult.IsMalicious || preAnalyzer.FormsAuthenticationTicketResult.IsMalicious || preAnalyzer.UserAuthenticationTicketResult.IsMalicious
        );        

        FormsAuthenticationCookieValid.BackColor = GetColor(preAnalyzer.FormsAuthenticationCookieResult.IsValid, preAnalyzer.FormsAuthenticationCookieResult.IsMalicious);
        FormsAuthenticationTicketValid.BackColor = GetColor(preAnalyzer.FormsAuthenticationTicketResult.IsValid, preAnalyzer.FormsAuthenticationTicketResult.IsMalicious);
        ServerAuthenticationTicketValid.BackColor = GetColor(preAnalyzer.UserAuthenticationTicketResult.IsValid, preAnalyzer.UserAuthenticationTicketResult.IsMalicious);

        /*
        TicketExpirationValid.BackColor = 
            ServerTicketExpirationValid.BackColor = 
            GetColor(preAnalyzer.UserAuthenticationTicketResult. TODO: Fix this
        */
        
        /*                
        if (isValid)
        {
            StatusColor.BackColor = Color.Green;
            StatusMessage.Text = "Request contains a valid FormsAuthenticationCookie and FormsAuthenticationTicket";
        }
        else
        {
            StatusColor.BackColor = Color.Red;
            StatusMessage.Text = "Request does not contain a valid FormsAuthenticationCookie and FormsAuthenticationTicket";
        }
        */
    }

    protected void TamperButton_Click(object sender, EventArgs e)
    {
        string formsAuthCookieValue = CookieValueServer.Text;
        FormsAuthenticationTicket newTicket = null;

        if (TamperFormsAuthenticationTicket.Checked)
        {
            newTicket = UserAuthentication.CreateFormsAuthTicket(
                TicketName.Text,
                TicketCookiePath.Text,
                TicketUserDataServer.Text,
                string.IsNullOrEmpty(TicketIssueDate.Text) ? (DateTime?)null : DateTime.Parse(TicketIssueDate.Text),
                string.IsNullOrEmpty(TicketExpiration.Text) ? (DateTime?)null : DateTime.Parse(TicketExpiration.Text),
                TicketIsPersistent.Checked
            );

            formsAuthCookieValue = FormsAuthentication.Encrypt(newTicket);
        }

        if (TamperFormsAuthenticationCookie.Checked)
        {
            UserAuthentication.ClearAuthCookie();

            HttpCookie newCookie = new HttpCookie(FormsAuthentication.FormsCookieName);
            newCookie.Domain = CookieDomain.Text;
            newCookie.Path = CookiePath.Text;
            newCookie.Secure = CookieSecure.Checked;
            newCookie.HttpOnly = true;

            DateTime newDate = DateTime.MinValue;
            if (!string.IsNullOrEmpty(CookieExpires.Text) && DateTime.TryParse(CookieExpires.Text, out newDate))
            {
                newCookie.Expires = newDate;
            }

            if (TamperFormsAuthenticationTicket.Checked)
            {
                newCookie.Value = formsAuthCookieValue;
            }
            else
            {
                newCookie.Value = CookieValueServer.Text;
            }

            Request.Cookies.Add(newCookie);  // Required for validation only
            Response.Cookies.Add(newCookie);
        }
        else if (TamperFormsAuthenticationTicket.Checked)
        {
            UserAuthentication.ClearAuthCookie();

            HttpCookie newCookie = new HttpCookie(FormsAuthentication.FormsCookieName, formsAuthCookieValue);
            newCookie.Path = FormsAuthentication.FormsCookiePath;
            newCookie.Secure = FormsAuthentication.RequireSSL;
            newCookie.HttpOnly = true;
            if (FormsAuthentication.CookieDomain != null)
            {
                newCookie.Domain = FormsAuthentication.CookieDomain;
            }
            if (TicketIsPersistent.Checked)
            {
                newCookie.Expires = newTicket.Expiration;
            }

            Request.Cookies.Add(newCookie);  // Required for validation only
            Response.Cookies.Add(newCookie);
        }

        if (TamperServerAuthenticationTicket.Checked)
        {
            string originalKey = Request["OriginalTicketKey"];
            string newKey = ServerKey.Text;

            UserAuthentication.Provider.RevokeTicket(originalKey);

            UserAuthenticationTicket serverAuthenticationTicket = new UserAuthenticationTicket();
            serverAuthenticationTicket.Key = ServerKey.Text;
            serverAuthenticationTicket.Username = ServerUsername.Text;
            serverAuthenticationTicket.HostAddress = ServerHostAddress.Text;
            serverAuthenticationTicket.CookieName = ServerCookieName.Text;
            serverAuthenticationTicket.CookieDomain = ServerCookieDomain.Text;
            serverAuthenticationTicket.CookiePath = ServerCookiePath.Text;
            serverAuthenticationTicket.CookieSecure = ServerCookieSecure.Checked;
            serverAuthenticationTicket.TicketIsPersistent = ServerTicketIsPersistent.Checked;
            serverAuthenticationTicket.TicketUserData = ServerTicketUserData.Text;
            serverAuthenticationTicket.TicketVersion = int.Parse(ServerTicketVersion.Text);
            serverAuthenticationTicket.TicketHash = ServerTicketHash.Text;

            DateTime ticketExpiration = DateTime.MinValue;
            DateTime ticketIssueDate = DateTime.MinValue;

            if (DateTime.TryParse(ServerTicketExpiration.Text, out ticketExpiration))
            {
                serverAuthenticationTicket.TicketExpiration = ticketExpiration;
            }

            if (DateTime.TryParse(ServerTicketIssueDate.Text, out ticketIssueDate))
            {
                serverAuthenticationTicket.TicketIssueDate = ticketIssueDate;
            }

            UserAuthentication.Provider.InsertTicket(serverAuthenticationTicket, ticketExpiration);
        }

        Response.Redirect(Request.RawUrl, false);
        // postAnalyzer = new FormsAuthenticationAnalyzer(Request.Cookies[FormsAuthentication.FormsCookieName], true);       
        // BindFields();
        // ValidateFields();
    }

    private string Wrap(string input)
    {
        if (string.IsNullOrEmpty(input)) return string.Empty;
        int i = 0;
        StringBuilder wrapper = new StringBuilder();
        while (i < input.Length)
        {
            string line = input.Substring(i, Math.Min(input.Length - i, 50));
            wrapper.Append(line + "<br />");
            i += line.Length;
        }
        return wrapper.ToString();
    }

    private Color GetColor(bool isValid, bool isMalicious)
    {
        if (isMalicious)
            return Color.Black;
        else if (isValid)
            return Color.Green;
        else
            return Color.Red;
    }


    private Color GetColor(bool isValid)
    {
        return isValid ? Color.Green : Color.Red;
    }
}