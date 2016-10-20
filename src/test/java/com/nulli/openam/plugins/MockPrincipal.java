package com.nulli.openam.plugins;
import java.security.Principal;

public class MockPrincipal implements Principal {
	String name;
	
	MockPrincipal(String name){
		this.name = name;
		
	}

	@Override
	public String getName() {
		return name;
	}

}
