package com.nulli.openam.plugins;

import java.net.InetAddress;
import java.security.Principal;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import com.iplanet.sso.SSOException;
import com.iplanet.sso.SSOToken;
import com.iplanet.sso.SSOTokenID;
import com.iplanet.sso.SSOTokenListener;

public class MockToken implements SSOToken {

	@Override
	public void addSSOTokenListener(SSOTokenListener arg0) throws SSOException {
		// TODO Auto-generated method stub
		
	}

	@Override
	public String dereferenceRestrictedTokenID(SSOToken arg0, String arg1) throws SSOException {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public int getAuthLevel() throws SSOException {
		// TODO Auto-generated method stub
		return 0;
	}

	@Override
	public String getAuthType() throws SSOException {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public String getHostName() throws SSOException {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public InetAddress getIPAddress() throws SSOException {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public long getIdleTime() throws SSOException {
		// TODO Auto-generated method stub
		return 0;
	}

	@Override
	public long getMaxIdleTime() throws SSOException {
		// TODO Auto-generated method stub
		return 0;
	}

	@Override
	public long getMaxSessionTime() throws SSOException {
		// TODO Auto-generated method stub
		return 0;
	}

	@Override
	public Principal getPrincipal() throws SSOException {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public String getProperty(String arg0) throws SSOException {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public String getProperty(String arg0, boolean arg1) throws SSOException {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public long getTimeLeft() throws SSOException {
		// TODO Auto-generated method stub
		return 0;
	}

	@Override
	public SSOTokenID getTokenID() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public boolean isTokenRestricted() throws SSOException {
		// TODO Auto-generated method stub
		return false;
	}

	@Override
	public void setProperty(String arg0, String arg1) throws SSOException {
		// TODO Auto-generated method stub
		
	}

	@Override
	public Map<String, String> getProperties() throws SSOException {
		Map<String, String> result = new HashMap();
		return Collections.unmodifiableMap(result);
	}

}
