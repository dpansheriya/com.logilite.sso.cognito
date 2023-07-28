/******************************************************************************
	 * Copyright (C) 2016 Logilite Technologies LLP								  *
 * This program is free software; you can redistribute it and/or modify it    *
 * under the terms version 2 of the GNU General Public License as published   *
 * by the Free Software Foundation. This program is distributed in the hope   *
 * that it will be useful, but WITHOUT ANY WARRANTY; without even the implied *
 * warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.           *
 * See the GNU General Public License for more details.                       *
 * You should have received a copy of the GNU General Public License along    *
 * with this program; if not, write to the Free Software Foundation, Inc.,    *
 * 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA.                     *
 *****************************************************************************/
package com.logilite.sso.cognito.principal;

import java.io.IOException;
import java.text.ParseException;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.adempiere.base.sso.ISSOPrincipalService;
import org.adempiere.base.sso.SSOUtils;
import org.compiere.model.I_SSO_PrincipalConfig;
import org.compiere.util.Language;
import org.pac4j.core.client.Clients;
import org.pac4j.core.config.Config;
import org.pac4j.jee.http.adapter.JEEHttpActionAdapter;
import org.pac4j.oidc.config.OidcConfiguration;

public class CognitoSSOPrincipal implements ISSOPrincipalService
{

	protected I_SSO_PrincipalConfig	principalConfig;

	private CognitoSSOHandler		handler;
	private CognitoOidcClient		clientWebui;
	private CognitoOidcClient		clientMonitior;
	private CognitoOidcClient		clientOsgi;

	public CognitoSSOPrincipal(I_SSO_PrincipalConfig principalConfig)
	{
		this.principalConfig = principalConfig;
		OidcConfiguration configuration = new OidcConfiguration();
		configuration.setClientId(principalConfig.getSSO_ApplicationClientID());
		configuration.setSecret(principalConfig.getSSO_ApplicationSecretKey());
		configuration.setScope("openid email profile");
		configuration.setResponseType("code");
		// TODO have to check a way to run with state and none as it is more secure
		configuration.setUseNonce(false);
		configuration.setWithState(false);

		clientWebui = new CognitoOidcClient(configuration, principalConfig);
		clientWebui.setCallbackUrl(principalConfig.getSSO_ApplicationRedirectURIs());
		clientWebui.setName(principalConfig.getSSO_Provider() + SSOUtils.SSO_MODE_WEBUI);

		clientMonitior = new CognitoOidcClient(configuration, principalConfig);
		clientMonitior.setCallbackUrl(principalConfig.getSSO_IDempMonitorRedirectURIs());
		clientMonitior.setName(principalConfig.getSSO_Provider() + SSOUtils.SSO_MODE_MONITOR);

		clientOsgi = new CognitoOidcClient(configuration, principalConfig);
		clientOsgi.setCallbackUrl(principalConfig.getSSO_OSGIRedirectURIs());
		clientOsgi.setName(principalConfig.getSSO_Provider() + SSOUtils.SSO_MODE_OSGI);

		Clients clients = new Clients(clientWebui, clientMonitior, clientOsgi);
		Config oidcConfig = new Config(clients);

		handler = new CognitoSSOHandler(this, oidcConfig, principalConfig, JEEHttpActionAdapter.INSTANCE);
	}

	@Override
	public boolean hasAuthenticationCode(HttpServletRequest request, HttpServletResponse response)
	{
		return handler.hasAuthenticationCode(request, response);
	}

	@Override
	public void getAuthenticationToken(HttpServletRequest request, HttpServletResponse response, String redirectMode) throws Throwable
	{
		handler.getAuthenticationToken(request, response, redirectMode);
	}

	@Override
	public boolean isAuthenticated(HttpServletRequest request, HttpServletResponse response)
	{
		if (request.getSession() == null)
			return false;
		return handler.isAuthenticated(request, response);
	}

	@Override
	public void redirectForAuthentication(HttpServletRequest request, HttpServletResponse response, String redirectMode) throws IOException
	{
		if (handler.isLoginRequestURL(request, redirectMode))
		{
			handler.redirectForAuthentication(request, response, redirectMode);
		}
	}

	public boolean isAccessTokenExpired(HttpServletRequest request, HttpServletResponse response)
	{
		return handler.isAccessTokenExpired(request, response);
	}

	public void refreshToken(HttpServletRequest request, HttpServletResponse response, String redirectMode) throws Throwable
	{
		handler.refreshToken(request, response);
	}

	@Override
	public void removePrincipalFromSession(HttpServletRequest request)
	{
		handler.removePrincipalFromSession(request);
	}

	@Override
	public String getUserName(Object result) throws ParseException
	{
		return handler.getUserName(result);
	}

	@Override
	public Language getLanguage(Object result) throws ParseException
	{
		return handler.getLanguage(result);
	}
	
	public CognitoOidcClient getClient(String redirectMode)
	{
		if (SSOUtils.SSO_MODE_OSGI.equalsIgnoreCase(redirectMode))
			return clientOsgi;
		else if (SSOUtils.SSO_MODE_MONITOR.equalsIgnoreCase(redirectMode))
			return clientMonitior;
		return clientWebui;
	}

	public String getClientName(String redirectMode)
	{
		if (SSOUtils.SSO_MODE_OSGI.equalsIgnoreCase(redirectMode))
			return clientOsgi.getName();
		else if (SSOUtils.SSO_MODE_MONITOR.equalsIgnoreCase(redirectMode))
			return clientMonitior.getName();
		return clientWebui.getName();
	}

	public OidcConfiguration getConfiguration(String redirectMode)
	{
		if (SSOUtils.SSO_MODE_OSGI.equalsIgnoreCase(redirectMode))
			return clientOsgi.getConfiguration();
		else if (SSOUtils.SSO_MODE_MONITOR.equalsIgnoreCase(redirectMode))
			return clientMonitior.getConfiguration();
		return clientWebui.getConfiguration();
	}

	public String getStateSessionAttributeName(String redirectMode)
	{
		if (SSOUtils.SSO_MODE_OSGI.equalsIgnoreCase(redirectMode))
			return clientOsgi.getStateSessionAttributeName();
		else if (SSOUtils.SSO_MODE_MONITOR.equalsIgnoreCase(redirectMode))
			return clientMonitior.getStateSessionAttributeName();
		return clientWebui.getStateSessionAttributeName();
	}
}
