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
package com.logilite.sso.cognito.factory;

import org.adempiere.base.sso.ISSOPrincipalFactory;
import org.adempiere.base.sso.ISSOPrincipalService;
import org.compiere.model.I_SSO_PrincipalConfig;

import com.logilite.sso.cognito.principal.CognitoSSOPrincipal;

public class CognitoPrincipalFactory implements ISSOPrincipalFactory
{
	@Override
	public ISSOPrincipalService getSSOPrincipalService(I_SSO_PrincipalConfig config)
	{
		if (config.getSSO_Provider().equals("COGNITO"))
		{
			return new CognitoSSOPrincipal(config);
		}
		return null;
	}
}
