package com.accenture.lkm.basic.entery.point;

import java.io.IOException;
import java.io.PrintWriter;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.www.BasicAuthenticationEntryPoint;

public class MyBasicAuthenticationEntryPoint extends BasicAuthenticationEntryPoint {

	final public static String REALM="MSDNAMESPACE";
	@Override
	public void afterPropertiesSet() throws Exception {
		// TODO Auto-generated method stub
		setRealmName(REALM);
		super.afterPropertiesSet();
	}

	
	// incase of authentication/ authorization fialure
	@Override
	public void commence(HttpServletRequest request,
			HttpServletResponse response, AuthenticationException authException)
			throws IOException, ServletException {
		// TODO Auto-generated method stub
		//super.commence(request, response, authException);
		response.addHeader("WWW-Authenticate", "Basic realm=" + getRealmName() + ""	);
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        PrintWriter writer = response.getWriter();
        writer.println("HTTP Status 401 - " + authException.getMessage());
		
		
	}
	
	
	
}


//http://www.baeldung.com/spring-security-basic-authentication
/*The realm, simply put, defines the scope/space 
 * that’s protected with Basic Auth (along with the root URL). 
 * That way you can – for example – 
 * have different realms for the same URL space and configure them differently.

The important point is that the realm isn’t optional – so when you’re using Basic Auth you need to define a realm – which is what that does.
Hope that clears things up.*/