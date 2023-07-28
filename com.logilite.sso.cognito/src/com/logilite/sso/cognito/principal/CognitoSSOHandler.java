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

import org.adempiere.base.sso.ISSOPrincipalService;
import org.adempiere.base.sso.SSOUtils;
import org.apache.http.client.utils.URIBuilder;
import org.compiere.model.I_SSO_PrincipalConfig;
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

	protected Config				config;
	protected I_SSO_PrincipalConfig	principalConfig;
	protected HttpActionAdapter		actionAdapter;
	protected DefaultCallbackLogic	auathLogic;
	// protected DefaultSecurityLogic securityLogic;
	protected CognitoSSOPrincipal	cognitoSSOPrincipal;

	public CognitoSSOHandler(CognitoSSOPrincipal cognitoSSOPrincipal, Config oidcConfig, I_SSO_PrincipalConfig principalConfig, JEEHttpActionAdapter actionAdapter)
	{
		setCognitoSSOPrincipal(cognitoSSOPrincipal);
		setConfig(oidcConfig);
		setPrincipalConfig(principalConfig);
		setHttpActionAdapter(actionAdapter);
		setUpSSOLogics();
	}

	public void setUpSSOLogics()
	{
		auathLogic = DefaultCallbackLogic.INSTANCE;
		// securityLogic = DefaultSecurityLogic.INSTANCE;
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
			request.getSession().setAttribute(ISSOPrincipalService.SSO_PRINCIPAL_SESSION_TOKEN, profiles.toArray()[0]);
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
			auathLogic.perform(context, sessionStore, config, actionAdapter, SSOUtils.getRedirectedURL(redirectMode, principalConfig), true, cognitoSSOPrincipal.getClientName(redirectMode));
			ProfileManager manager = new ProfileManager(context, sessionStore);
			List<UserProfile> profiles = manager.getProfiles();
			if (profiles != null && profiles.size() > 0)
			{
				setPrincipal(request.getSession(), profiles.get(0));
				afterUserAuth(request, response, context, sessionStore, profiles, null);
			}
		}
		else
		{
			// If Authentication can not be done redirect to login url as per mode.
			response.sendRedirect(SSOUtils.getRedirectedURL(redirectMode, principalConfig));
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
			setPrincipal(request.getSession(), profiles);
		}
	}

	public void setCognitoSSOPrincipal(CognitoSSOPrincipal cognitoSSOPrincipal)
	{
		this.cognitoSSOPrincipal = cognitoSSOPrincipal;
	}

	public void setConfig(Config config)
	{
		this.config = config;
	}

	public void setHttpActionAdapter(HttpActionAdapter actionAdapter)
	{
		this.actionAdapter = actionAdapter;
	}

	public void setPrincipalConfig(I_SSO_PrincipalConfig principalConfig)
	{
		this.principalConfig = principalConfig;
	}

	public WebContext newWebContext(HttpServletRequest request, HttpServletResponse response)
	{
		return FindBest.webContextFactory(null, config, new JEEContextFactory()).newContext(request, response);
	}

	public SessionStore newSessionStore(HttpServletRequest request, HttpServletResponse response)
	{
		return FindBest.sessionStoreFactory(null, config, new JEESessionStoreFactory()).newSessionStore(request, response);
	}

	public void setPrincipal(HttpSession httpSession, Object token)
	{
		httpSession.setAttribute(ISSOPrincipalService.SSO_PRINCIPAL_SESSION_TOKEN, token);
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
		return request.getSession().getAttribute(ISSOPrincipalService.SSO_PRINCIPAL_SESSION_TOKEN) != null;
	}

	public boolean isAccessTokenExpired(HttpServletRequest request, HttpServletResponse response)
	{
		if (request.getSession().getAttribute(ISSOPrincipalService.SSO_PRINCIPAL_SESSION_TOKEN) != null
			&& request.getSession().getAttribute(ISSOPrincipalService.SSO_PRINCIPAL_SESSION_TOKEN) instanceof UserProfile)
		{
			UserProfile obj = ((UserProfile) request.getSession().getAttribute(ISSOPrincipalService.SSO_PRINCIPAL_SESSION_TOKEN));
			return ((Date) obj.getAttribute("exp")).before(new Date());
		}
		return false;
	}

	public void removePrincipalFromSession(HttpServletRequest request)
	{
		request.getSession().removeAttribute(ISSOPrincipalService.SSO_PRINCIPAL_SESSION_TOKEN);
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

	/**
	 * Redirect to login URL
	 * 
	 * @param request
	 * @param response
	 * @param redirectMode
	 */
	public void sendAuthRedirect(HttpServletRequest request, HttpServletResponse response, String redirectMode)
	{

		// state parameter to validate response from Authorization server and nonce
		State state = null;
		Nonce nonce = null;
		WebContext context = newWebContext(request, response);
		SessionStore sessionStore = newSessionStore(request, response);
		request.getSession().setAttribute(SSO_WEB_CONTEXT, context);
		request.getSession().setAttribute(SSO_SESSION_STORE, sessionStore);

		if (cognitoSSOPrincipal.getConfiguration(redirectMode).isWithState())
		{
			state = new State(cognitoSSOPrincipal.getConfiguration(redirectMode).getStateGenerator().generateValue(context, sessionStore));
			sessionStore.set(context, cognitoSSOPrincipal.getStateSessionAttributeName(redirectMode), state);
		}

		if (cognitoSSOPrincipal.getConfiguration(redirectMode).isUseNonce())
		{
			nonce = new Nonce();
			sessionStore.set(context, cognitoSSOPrincipal.getStateSessionAttributeName(redirectMode), nonce.getValue());
		}
		sessionStore.set(context, Pac4jConstants.REQUESTED_URL, SSOUtils.getRedirectedURL(redirectMode, principalConfig));

		response.setStatus(302);
		try
		{
			// load the Discovery configuration
			cognitoSSOPrincipal.getClient(redirectMode).getConfiguration().setDiscoveryURI(principalConfig.getSSO_ApplicationDiscoveryURI());
			cognitoSSOPrincipal.getClient(redirectMode).init(true);

			String authorizationCodeUrl = getAuthorizationCodeUrl(state, nonce, redirectMode);
			response.sendRedirect(authorizationCodeUrl);

			// Use Authorize endpoint for user login., TODO find a way to revoke the user session
			// ProfileManager manager = new ProfileManager(context, sessionStore);
			// manager.removeProfiles();
			// securityLogic.perform(context, sessionStore, config, null, actionAdapter,
			// cognitoSSOPrincipal.getClientName(redirectMode), null, null);
			// securityLogic.setLoadProfilesFromSession(false);
		}
		catch (Exception e)
		{
			log.log(Level.SEVERE, "Redirect fail for auth", e);
		}
	}

	/**
	 * Create Redirect URL for login
	 * 
	 * @param  state
	 * @param  nonce
	 * @param  redirectMode
	 * @return
	 */
	private String getAuthorizationCodeUrl(State state, Nonce nonce, String redirectMode)
	{
		URL url = null;
		try
		{
			OidcConfiguration configuration = cognitoSSOPrincipal.getConfiguration(redirectMode);

			String loginURL = cognitoSSOPrincipal.getClient(redirectMode).getConfiguration().findProviderMetadata().getAuthorizationEndpointURI().toString().replace("oauth2/authorize", "login");
			URIBuilder builder = new URIBuilder(loginURL);
			builder.addParameter("scope", configuration.getScope());
			builder.addParameter("response_type", configuration.getResponseType());
			builder.addParameter("redirect_uri", SSOUtils.getRedirectedURL(redirectMode, principalConfig));
			if (state != null)
				builder.addParameter("state", state.toString());
			if (nonce != null)
				builder.addParameter("nonce", nonce.toString());
			builder.addParameter("client_id", principalConfig.getSSO_ApplicationClientID());

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
