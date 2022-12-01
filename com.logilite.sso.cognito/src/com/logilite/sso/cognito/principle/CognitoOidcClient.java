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

import org.compiere.model.I_SSO_PrincipleConfig;
import org.pac4j.core.http.callback.NoParameterCallbackUrlResolver;
import org.pac4j.oidc.client.OidcClient;
import org.pac4j.oidc.config.OidcConfiguration;
import org.pac4j.oidc.logout.OidcLogoutActionBuilder;
import org.pac4j.oidc.profile.OidcProfile;
import org.pac4j.oidc.profile.OidcProfileDefinition;
import org.pac4j.oidc.profile.creator.OidcProfileCreator;

public class CognitoOidcClient extends OidcClient
{

	String discoveryURI;
	public CognitoOidcClient()
	{
	}

	public CognitoOidcClient(final OidcConfiguration configuration, I_SSO_PrincipleConfig principleConfig)
	{
		super(configuration);
		discoveryURI = principleConfig.getSSO_ApplicationDiscoveryURI();
	}

	@Override
	protected void internalInit(final boolean forceReinit)
	{
		getConfiguration().defaultDiscoveryURI(discoveryURI);
		final var profileCreator = new OidcProfileCreator(getConfiguration(), this);
		profileCreator.setProfileDefinition(new OidcProfileDefinition(x -> new OidcProfile()));
		defaultProfileCreator(profileCreator);
		defaultLogoutActionBuilder(new OidcLogoutActionBuilder(getConfiguration()));
		setCallbackUrlResolver(new NoParameterCallbackUrlResolver());
		super.internalInit(forceReinit);
	}
}
