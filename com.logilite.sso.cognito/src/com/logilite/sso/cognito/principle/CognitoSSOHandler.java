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
import java.net.MalformedURLException;
import java.net.URISyntaxException;
import java.net.URL;
import java.util.Collection;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.logging.Level;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.adempiere.base.sso.ISSOPrinciple;
import org.adempiere.base.sso.SSOUtils;
import org.apache.http.client.utils.URIBuilder;
import org.compiere.model.I_SSO_PrincipleConfig;
import org.compiere.model.MSysConfig;
import org.compiere.util.CLogger;
import org.compiere.util.Language;
import org.compiere.util.Util;
import org.pac4j.core.config.Config;
import org.pac4j.core.context.WebContext;
import org.pac4j.core.context.session.SessionStore;
import org.pac4j.core.engine.DefaultCallbackLogic;
import org.pac4j.core.http.adapter.HttpActionAdapter;
import org.pac4j.core.profile.ProfileManager;
import org.pac4j.core.profile.UserProfile;
import org.pac4j.core.util.FindBest;
import org.pac4j.core.util.Pac4jConstants;
import org.pac4j.jee.context.JEEContextFactory;
import org.pac4j.jee.context.session.JEESessionStoreFactory;
import org.pac4j.jee.http.adapter.JEEHttpActionAdapter;
import org.pac4j.oidc.config.OidcConfiguration;

import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.openid.connect.sdk.Nonce;

public class CognitoSSOHandler
{

	/** Logger */
	protected static CLogger		log					= CLogger.getCLogger(CognitoSSOHandler.class);

	protected static final String	SSO_WEB_CONTEXT		= "sso.WebContext";
	protected static final String	SSO_SESSION_STORE	= "sso.SessionStore";

	protected String				domainURL;
	protected Config				config;
	protected I_SSO_PrincipleConfig	principleConfig;
	protected HttpActionAdapter		actionAdapter;
	protected DefaultCallbackLogic	auathLogic;
	protected CognitoSSOPrinciple	cognitoSSOPrinciple;

	public CognitoSSOHandler(	CognitoSSOPrinciple cognitoSSOPrinciple, Config oidcConfig, I_SSO_PrincipleConfig principleConfig,
								JEEHttpActionAdapter actionAdapter)
	{
		setCognitoSSOPrinciple(cognitoSSOPrinciple);
		setConfig(oidcConfig);
		setPrincipleConfig(principleConfig);
		setHttpActionAdapter(actionAdapter);
		setDomainURL(principleConfig.getSSO_ApplicationDomain());
		setUpSSOLogics();
	}

	public void setUpSSOLogics()
	{
		auathLogic = DefaultCallbackLogic.INSTANCE;
	}

	public void redirectForAuthentication(HttpServletRequest request, HttpServletResponse response, String redirectMode)
	{
		sendAuthRedirect(request, response, redirectMode);
	}

	public void afterUserAuth(HttpServletRequest request, HttpServletResponse response, WebContext ctx,
		SessionStore session, Collection<UserProfile> profiles, Object[] parameters) throws IOException
	{
		if (profiles != null && profiles.size() > 0)
		{
			request.getSession().setAttribute(ISSOPrinciple.SSO_PRINCIPLE_SESSION_NAME, profiles.toArray()[0]);
			String currentUri = request.getRequestURL().toString();
			response.sendRedirect(currentUri);
		}
	}

	public void getAuthenticationToken(HttpServletRequest request, HttpServletResponse response, String redirectMode) throws IOException
	{
		WebContext context = (WebContext) request.getSession().getAttribute(SSO_WEB_CONTEXT);
		SessionStore sessionStore = (SessionStore) request.getSession().getAttribute(SSO_SESSION_STORE);
		if (context != null && sessionStore != null)
		{
			auathLogic.perform(context, sessionStore, config, actionAdapter, SSOUtils.getRedirectedURL(redirectMode, principleConfig), true, cognitoSSOPrinciple.getClientName(redirectMode));
			ProfileManager manager = new ProfileManager(context, sessionStore);
			List<UserProfile> profiles = manager.getProfiles();
			if (profiles != null && profiles.size() > 0)
			{
				setPrinciple(request.getSession(), profiles.get(0));
				afterUserAuth(request, response, context, sessionStore, profiles, null);
			}
		}
	}

	public void refreshToken(HttpServletRequest request, HttpServletResponse response)
	{
		WebContext context = (WebContext) request.getSession().getAttribute(SSO_WEB_CONTEXT);
		SessionStore sessionStore = (SessionStore) request.getSession().getAttribute(SSO_SESSION_STORE);
		ProfileManager manager = new ProfileManager(context, sessionStore);
		manager.setConfig(config);
		List<UserProfile> profiles = manager.getProfiles();
		if (profiles != null && profiles.size() > 0)
		{
			setPrinciple(request.getSession(), profiles);
		}
	}

	public void setCognitoSSOPrinciple(CognitoSSOPrinciple cognitoSSOPrinciple)
	{
		this.cognitoSSOPrinciple = cognitoSSOPrinciple;
	}

	public void setConfig(Config config)
	{
		this.config = config;
	}

	public void setHttpActionAdapter(HttpActionAdapter actionAdapter)
	{
		this.actionAdapter = actionAdapter;
	}

	public void setDomainURL(String domainURL)
	{
		if (!domainURL.endsWith("/"))
			domainURL = domainURL + "/";
		this.domainURL = domainURL;
	}

	public void setPrincipleConfig(I_SSO_PrincipleConfig principleConfig)
	{
		this.principleConfig = principleConfig;
	}

	public WebContext newWebContext(HttpServletRequest request, HttpServletResponse response)
	{
		return FindBest.webContextFactory(null, config, new JEEContextFactory()).newContext(request, response);
	}

	public SessionStore newSessionStore(HttpServletRequest request, HttpServletResponse response)
	{
		return FindBest
						.sessionStoreFactory(null, config, new JEESessionStoreFactory())
						.newSessionStore(request,
										response);
	}

	public void setPrinciple(HttpSession httpSession, Object token)
	{
		httpSession.setAttribute(ISSOPrinciple.SSO_PRINCIPLE_SESSION_NAME, token);
	}

	/**
	 * Check is code exist in the request to get token
	 * 
	 * @param  request
	 * @param  response
	 * @return
	 */
	public boolean hasAuthenticationCode(HttpServletRequest request, HttpServletResponse response)
	{
		Map<String, String[]> httpParameters = request.getParameterMap();
		boolean containsCode = httpParameters.containsKey("code");
		return containsCode;
	}

	/**
	 * Prevent duplicate request as it cause state mismatch error on response
	 * 
	 * @param  request
	 * @param  redirectMode
	 * @return
	 */
	public boolean isLoginRequestURL(HttpServletRequest request, String redirectMode)
	{
		return (!Util.isEmpty(request.getServletPath())
				&& ((SSOUtils.SSO_MODE_WEBUI.equalsIgnoreCase(redirectMode) && (request.getServletPath().endsWith("index.zul") || request.getServletPath().equalsIgnoreCase("/")))
					|| request.getServletPath().startsWith("/system/console")
						|| request.getServletPath().startsWith("/idempiereMonitor")));
	}

	public boolean isAuthenticated(HttpServletRequest request, HttpServletResponse response)
	{
		return request.getSession().getAttribute(ISSOPrinciple.SSO_PRINCIPLE_SESSION_NAME) != null;
	}

	public boolean isAccessTokenExpired(HttpServletRequest request, HttpServletResponse response)
	{
		if (request.getSession().getAttribute(ISSOPrinciple.SSO_PRINCIPLE_SESSION_NAME) != null
			&& request.getSession().getAttribute(ISSOPrinciple.SSO_PRINCIPLE_SESSION_NAME) instanceof UserProfile)
		{
			UserProfile obj = ((UserProfile) request
							.getSession()
							.getAttribute(ISSOPrinciple.SSO_PRINCIPLE_SESSION_NAME));
			return ((Date) obj.getAttribute("exp")).before(new Date());
		}
		return false;
	}

	public void removePrincipleFromSession(HttpServletRequest request)
	{
		request.getSession().removeAttribute(ISSOPrinciple.SSO_PRINCIPLE_SESSION_NAME);
		request.getSession().removeAttribute(SSO_WEB_CONTEXT);
		request.getSession().removeAttribute(SSO_SESSION_STORE);
	}

	public String getUserName(Object result)
	{
		if (result != null && result instanceof UserProfile)
		{
			boolean isEmailLogin = MSysConfig.getBooleanValue(MSysConfig.USE_EMAIL_FOR_LOGIN, false);
			UserProfile user = (UserProfile) result;
			if (isEmailLogin)
				return (String) user.getAttribute("email");
			else
				return (String) user.getAttribute("name");
		}
		return null;
	}

	public Language getLanguage(Object result)
	{
		return Language.getBaseLanguage();
	}

	public void sendAuthRedirect(HttpServletRequest request, HttpServletResponse response, String redirectMode)
	{

		// state parameter to validate response from Authorization server and nonce
		State state = null;
		Nonce nonce = null;
		WebContext context = newWebContext(request, response);
		SessionStore sessionStore = newSessionStore(request, response);
		request.getSession().setAttribute(SSO_WEB_CONTEXT, context);
		request.getSession().setAttribute(SSO_SESSION_STORE, sessionStore);

		if (cognitoSSOPrinciple.getConfiguration(redirectMode).isWithState())
		{
			state = new State(cognitoSSOPrinciple.getConfiguration(redirectMode).getStateGenerator().generateValue(context, sessionStore));
			sessionStore.set(context, cognitoSSOPrinciple.getStateSessionAttributeName(redirectMode), state);
		}

		if (cognitoSSOPrinciple.getConfiguration(redirectMode).isUseNonce())
		{
			nonce = new Nonce();
			sessionStore.set(context, cognitoSSOPrinciple.getStateSessionAttributeName(redirectMode), nonce.getValue());
		}
		sessionStore.set(context, Pac4jConstants.REQUESTED_URL, SSOUtils.getRedirectedURL(redirectMode, principleConfig));

		response.setStatus(302);
		String authorizationCodeUrl = getAuthorizationCodeUrl(state, nonce, redirectMode);
		try
		{
			response.sendRedirect(authorizationCodeUrl);
		}
		catch (IOException e)
		{
			log.log(Level.SEVERE, "Redirect fail for auth", e);
		}
	}

	private String getAuthorizationCodeUrl(State state, Nonce nonce, String redirectMode)
	{
		URL url = null;
		try
		{
			OidcConfiguration configuration = cognitoSSOPrinciple.getConfiguration(redirectMode);

			URIBuilder builder = new URIBuilder(domainURL.trim() + "login");
			builder.addParameter("scope", configuration.getScope());
			builder.addParameter("response_type", configuration.getResponseType());
			builder.addParameter("redirect_uri", SSOUtils.getRedirectedURL(redirectMode, principleConfig));
			if (state != null)
				builder.addParameter("state", state.toString());
			if (nonce != null)
				builder.addParameter("nonce", nonce.toString());
			builder.addParameter("client_id", principleConfig.getSSO_ApplicationClientID());

			url = builder.build().toURL();
		}
		catch (MalformedURLException e)
		{
			log.log(Level.SEVERE, "Login request fail", e);
		}
		catch (URISyntaxException e)
		{
			log.log(Level.SEVERE, "Login request fail", e);
		}
		return url.toString();
	}
}
