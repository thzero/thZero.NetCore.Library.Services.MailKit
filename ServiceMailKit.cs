/* ------------------------------------------------------------------------- *
thZero.NetCore.Library.MailKit
Copyright (C) 2016-2021 thZero.com

<development [at] thzero [dot] com>

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

	http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
 * ------------------------------------------------------------------------- */

using System;
using System.Threading.Tasks;

using Microsoft.Extensions.Logging;

using MailKit.Net.Smtp;
using MimeKit;

namespace thZero.Services
{
	public sealed class ServiceMailKitFactory : Internal.ServiceMailKitBase<ServiceMailKitFactory>, IServiceMail
    {
		private static readonly thZero.Services.IServiceLog log = thZero.Factory.Instance.RetrieveLogger(System.Reflection.MethodBase.GetCurrentMethod().DeclaringType);

        public ServiceMailKitFactory() : base(log, null)
        {
        }
    }

    public sealed class ServiceMailKit : ServiceBase<ServiceMailKit>, IServiceMail
    {
        public ServiceMailKit(ILogger<ServiceMailKit> logger) : base(logger)
        {
            _instance = new Internal.ServiceMailKitBase<ServiceMailKit>(null, logger);
        }

        #region Public Methods
        public void Send(string toAddress, string subject, string body, Configuration.ApplicationEmail config)
        {
            _instance.Send(toAddress, subject, body, config);
        }

        public void Send(string toAddress, string subject, string body, string fromAddress, Configuration.ApplicationEmail config)
        {
            _instance.Send(toAddress, subject, body, fromAddress, config);
        }

        public async Task<bool> SendAsync(string toAddress, string subject, string body, Configuration.ApplicationEmail config)
        {
            return await _instance.SendAsync(toAddress, subject, body, config);
        }

        public async Task<bool> SendAsync(string toAddress, string subject, string body, string fromAddress, Configuration.ApplicationEmail config)
        {
            return await _instance.SendAsync(toAddress, subject, body, fromAddress, config);
        }

        public void Send(string toAddress, string toDisplayName, string subject, string body, string fromAddress, string fromDisplayName, Configuration.ApplicationEmail config)
        {
            _instance.Send(toAddress, toDisplayName, subject, body, fromAddress, fromDisplayName, config);
        }

        public async Task<bool> SendAsync(string toAddress, string toDisplayName, string subject, string body, string fromAddress, string fromDisplayName, Configuration.ApplicationEmail config)
        {
            return await _instance.SendAsync(toAddress, toDisplayName, subject, body, fromAddress, fromDisplayName, config);
        }
        #endregion

        #region Fields
        private static Internal.ServiceMailKitBase<ServiceMailKit> _instance;
        #endregion
    }
}

namespace thZero.Services.Internal
{
    public class ServiceMailKitBase<TService> : IntermediaryServiceBase<TService>
    {
        public ServiceMailKitBase(thZero.Services.IServiceLog log, ILogger<TService> logger) : base(log, logger)
        {
        }

        #region Public Methods
        public void Send(string toAddress, string subject, string body, Configuration.ApplicationEmail config)
        {
            Send(new MailboxAddress("send", toAddress), subject, body, null, config);
        }

        public void Send(string toAddress, string subject, string body, string fromAddress, Configuration.ApplicationEmail config)
        {
            Enforce.AgainstNullOrEmpty(() => fromAddress);

            Send(new MailboxAddress("send", toAddress), subject, body, new MailboxAddress("send", fromAddress), config);
        }

        public async Task<bool> SendAsync(string toAddress, string subject, string body, Configuration.ApplicationEmail config)
        {
            return await SendAsync(new MailboxAddress("send", toAddress), subject, body, null, config);
        }

        public async Task<bool> SendAsync(string toAddress, string subject, string body, string fromAddress, Configuration.ApplicationEmail config)
        {
            return await SendAsync(new MailboxAddress("send", toAddress), subject, body, new MailboxAddress("send", fromAddress), config);
        }

        public void Send(string toAddress, string toDisplayName, string subject, string body, string fromAddress, string fromDisplayName, Configuration.ApplicationEmail config)
        {
            const string Declaration = "Send";

            try
            {
                MailboxAddress address = null;
                if (!string.IsNullOrEmpty(fromAddress))
                    address = new MailboxAddress(fromAddress, fromDisplayName);

                Send(new MailboxAddress(toAddress, toDisplayName), subject, body, address, config);
            }
            catch (Exception ex)
            {
                Log?.Error(Declaration, ex);
                Logger?.LogError(Declaration, ex);
                throw;
            }
        }

        public async Task<bool> SendAsync(string toAddress, string toDisplayName, string subject, string body, string fromAddress, string fromDisplayName, Configuration.ApplicationEmail config)
        {
            const string Declaration = "Send";

            try
            {
                MailboxAddress address = null;
                if (!string.IsNullOrEmpty(fromAddress))
                    address = new MailboxAddress(fromAddress, fromDisplayName);

                return await SendAsync(new MailboxAddress(toAddress, toDisplayName), subject, body, address, config);
            }
            catch (Exception ex)
            {
                Log?.Error(Declaration, ex);
                Logger?.LogError(Declaration, ex);
                throw;
            }
        }
        #endregion

        #region Private Methods
        private void Send(MailboxAddress toAddress, string subject, string body, MailboxAddress fromAddress, Configuration.ApplicationEmail config)
        {
            Enforce.AgainstNull(() => toAddress);
            Enforce.AgainstNullOrEmpty(() => subject);
            Enforce.AgainstNullOrEmpty(() => body);

            const string Declaration = "Send";

            try
            {
                if ((config == null) && !config.Enabled)
                    return;

                if (string.IsNullOrEmpty(config.Smtp.Server))
                    //throw new EmailInvalidConfigurationException("Unable to send email, no Smtp.Server specified in configuration.");
                    throw new Exception("Unable to send email, no Smtp.Server specified in configuration.");

                if (fromAddress == null)
                    fromAddress = new MailboxAddress(config.AddressFrom, config.AddressFrom);

                MimeMessage message = new()
                {
                    Subject = subject,
                    Body = new TextPart("plain")
                    {
                        Text = body
                    }
                };
                message.From.Add(fromAddress);
                message.To.Add(toAddress);

                using SmtpClient client = new();
                try
                {
                    client.ServerCertificateValidationCallback = (s, c, h, e) => true;
                    client.Connect(config.Smtp.Server, Convert.ToInt32(config.Smtp.Port), true);
                    // Note: since we don't have an OAuth2 token, disable
                    // the XOAUTH2 authentication mechanism.
                    client.AuthenticationMechanisms.Remove("XOAUTH2");
                    client.Authenticate(config.Smtp.User, config.Smtp.UserPassword);

                    client.Send(message);
                }
                finally
                {
                    if (client != null)
                    {
                        if (client.IsConnected)
                            client.Disconnect(true);
                    }
                }
            }
            catch (Exception ex)
            {
                Log?.Error(Declaration, ex);
                Logger?.LogError(Declaration, ex);
                throw;
            }
        }

        private async Task<bool> SendAsync(MailboxAddress toAddress, string subject, string body, MailboxAddress fromAddress, Configuration.ApplicationEmail config)
        {
            Enforce.AgainstNull(() => toAddress);
            Enforce.AgainstNullOrEmpty(() => subject);
            Enforce.AgainstNullOrEmpty(() => body);

            const string Declaration = "Send";

            try
            {
                if ((config == null) && !config.Enabled)
                    return await Task.FromResult(false);

                if (string.IsNullOrEmpty(config.Smtp.Server))
                    //throw new EmailInvalidConfigurationException("Unable to send email, no Smtp.Server specified in configuration.");
                    throw new Exception("Unable to send email, no Smtp.Server specified in configuration.");

                if (fromAddress == null)
                    fromAddress = new MailboxAddress(config.AddressFrom, config.AddressFrom);

                MimeMessage message = new()
                {
                    Subject = subject,
                    Body = new TextPart("plain")
                    {
                        Text = body
                    }
                };
                message.From.Add(fromAddress);
                message.To.Add(toAddress);

                using (SmtpClient client = new())
                {
                    try
                    {
                        client.ServerCertificateValidationCallback = (s, c, h, e) => true;
                        client.Connect(config.Smtp.Server, Convert.ToInt32(config.Smtp.Port), false);
                        // Note: since we don't have an OAuth2 token, disable
                        // the XOAUTH2 authentication mechanism.
                        client.AuthenticationMechanisms.Remove("XOAUTH2");
                        client.Authenticate(config.Smtp.User, config.Smtp.UserPassword);

                        await client.SendAsync(message);
                    }
                    finally
                    {
                        if (client != null)
                        {
                            if (client.IsConnected)
                                client.Disconnect(true);
                        }
                    }
                }

                return true;
            }
            catch (Exception ex)
            {
                Log?.Error(Declaration, ex);
                Logger?.LogError(Declaration, ex);
                throw;
            }
        }
        #endregion
    }
}