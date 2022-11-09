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
package com.logilite.sso.cognito.principle;

import java.io.IOException;
import java.text.ParseException;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.adempiere.webui.sso.ISSOPrinciple;
import org.compiere.model.I_SSO_PrincipleConfig;
import org.compiere.util.Language;
import org.pac4j.core.client.Clients;
import org.pac4j.core.config.Config;
import org.pac4j.jee.http.adapter.JEEHttpActionAdapter;
import org.pac4j.oidc.client.OidcClient;
import org.pac4j.oidc.config.OidcConfiguration;

public class CognitoSSOPrinciple implements ISSOPrinciple {

	private CognitoSSOHandler handler;

	public CognitoSSOPrinciple(I_SSO_PrincipleConfig principleConfig) {

		OidcConfiguration configuration = new OidcConfiguration();
		configuration.setClientId(principleConfig.getSSO_ApplicationClientID());
		configuration.setSecret(principleConfig.getSSO_ApplicationSecretKey());
		configuration.setScope("openid email profile");
		configuration.setResponseType("code");
		configuration.setUseNonce(true);

		OidcClient client = new CognitoOidcClient(configuration, principleConfig);
		client.setName(principleConfig.getSSO_Provider());

		Clients clients = new Clients(principleConfig.getSSO_ApplicationRedirectURIs(), client);
		Config oidcConfig = new Config(clients);

		handler = new CognitoSSOHandler(client, oidcConfig, principleConfig, JEEHttpActionAdapter.INSTANCE);
	}

	@Override
	public boolean hasAuthenticationCode(HttpServletRequest request, HttpServletResponse response) {
		return handler.hasAuthenticationCode(request, response);
	}

	@Override
	public void getAuthenticationToken(HttpServletRequest request, HttpServletResponse response) throws Throwable {
		handler.getAuthenticationToken(request, response);
	}

	@Override
	public boolean isAuthenticated(HttpServletRequest request, HttpServletResponse response) {
		if (request.getSession() == null)
			return false;
		return handler.isAuthenticated(request, response);
	}

	@Override
	public void redirectForAuthentication(HttpServletRequest request, HttpServletResponse response) throws IOException {
		if (handler.isLoginRequestURL(request)) {
			handler.redirectForAuthentication(request, response);
		}
	}

	@Override
	public boolean isAccessTokenExpired(HttpServletRequest request, HttpServletResponse response) {
		return handler.isAccessTokenExpired(request, response);
	}

	@Override
	public void refreshToken(HttpServletRequest request, HttpServletResponse response) throws Throwable {
		handler.refreshToken(request, response);
	}

	@Override
	public void removePrincipleFromSession(HttpServletRequest request) {
		handler.removePrincipleFromSession(request);
	}

	@Override
	public String getUserName(Object result) throws ParseException {
		return handler.getUserName(result);
	}

	@Override
	public Language getLanguage(Object result) throws ParseException {
		return handler.getLanguage(result);
	}
}