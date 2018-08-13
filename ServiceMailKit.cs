/* ------------------------------------------------------------------------- *
thZero.NetCore.Library.MailKit
Copyright (C) 2016-2018 thZero.com

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

using MailKit.Net.Smtp;
using MimeKit;

namespace thZero.Services
{
	public sealed class ServiceMailKit : IServiceMail
	{
		private static readonly thZero.Services.IServiceLog log = thZero.Factory.Instance.RetrieveLogger(System.Reflection.MethodBase.GetCurrentMethod().DeclaringType);

		#region Public Methods
		public void Send(string toAddress, string subject, string body, Configuration.ApplicationEmail config)
		{
			Send(new MailboxAddress(toAddress), subject, body, null, config);
		}

		public void Send(string toAddress, string subject, string body, string fromAddress, Configuration.ApplicationEmail config)
		{
			Enforce.AgainstNullOrEmpty(() => fromAddress);

			Send(new MailboxAddress(toAddress), subject, body, new MailboxAddress(fromAddress), config);
		}

		public async Task<bool> SendAsync(string toAddress, string subject, string body, Configuration.ApplicationEmail config)
		{
			return await SendAsync(new MailboxAddress(toAddress), subject, body, null, config);
		}

		public async Task<bool> SendAsync(string toAddress, string subject, string body, string fromAddress, Configuration.ApplicationEmail config)
		{
			return await SendAsync(new MailboxAddress(toAddress), subject, body, new MailboxAddress(fromAddress), config);
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
				log.Error(Declaration, ex);
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
				log.Error(Declaration, ex);
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

				if (string.IsNullOrEmpty(config.SmtpServer))
					//throw new EmailInvalidConfigurationException("Unable to send email, no SmtpServer specified in configuration.");
					throw new Exception("Unable to send email, no SmtpServer specified in configuration.");

				if (fromAddress == null)
					fromAddress = new MailboxAddress(config.AddressFrom, config.AddressFrom);

				MimeMessage message = new MimeMessage()
				{
					Subject = subject,
					Body = new TextPart("plain")
					{
						Text = body
					}
				};
				message.From.Add(fromAddress);
				message.To.Add(toAddress);

				using (SmtpClient client = new SmtpClient())
				{
					try
					{
						client.ServerCertificateValidationCallback = (s, c, h, e) => true;
						client.Connect(config.SmtpServer, Convert.ToInt32(config.SmtpPort), true);
						// Note: since we don't have an OAuth2 token, disable
						// the XOAUTH2 authentication mechanism.
						client.AuthenticationMechanisms.Remove("XOAUTH2");
						client.Authenticate(config.SmtpUser, config.SmtpUserPassword);

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
			}
			catch (Exception ex)
			{
				log.Error(Declaration, ex);
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

				if (string.IsNullOrEmpty(config.SmtpServer))
					//throw new EmailInvalidConfigurationException("Unable to send email, no SmtpServer specified in configuration.");
					throw new Exception("Unable to send email, no SmtpServer specified in configuration.");

				if (fromAddress == null)
					fromAddress = new MailboxAddress(config.AddressFrom, config.AddressFrom);

				MimeMessage message = new MimeMessage()
				{
					Subject = subject,
					Body = new TextPart("plain")
					{
						Text = body
					}
				};
				message.From.Add(fromAddress);
				message.To.Add(toAddress);

				using (SmtpClient client = new SmtpClient())
				{
					try
					{
						client.ServerCertificateValidationCallback = (s, c, h, e) => true;
						client.Connect(config.SmtpServer, Convert.ToInt32(config.SmtpPort), false);
						// Note: since we don't have an OAuth2 token, disable
						// the XOAUTH2 authentication mechanism.
						client.AuthenticationMechanisms.Remove("XOAUTH2");
						client.Authenticate(config.SmtpUser, config.SmtpUserPassword);

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
				log.Error(Declaration, ex);
				throw;
			}
		}
		#endregion
	}
}