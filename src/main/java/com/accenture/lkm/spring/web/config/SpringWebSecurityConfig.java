package com.accenture.lkm.spring.web.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.PropertySource;
import org.springframework.context.support.PropertySourcesPlaceholderConfigurer;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;

import com.accenture.lkm.basic.entery.point.MyBasicAuthenticationEntryPoint;

// these annotations are used to declare this file as the Security File
@Configuration
@EnableWebSecurity
@PropertySource("classpath:com/accenture/lkm/resources/cst_conn.properties")
public class SpringWebSecurityConfig extends WebSecurityConfigurerAdapter {

	@Value("${cst_db_driver}")
	private String driverName;

	@Value("${cst_db_url_sec}")
	private String securityUrl;

	@Value("${cst_user}")
	private String userName;

	@Value("${cst_password}")
	private String password;

	@Override
	protected void configure(HttpSecurity http) throws Exception {

		http.csrf().disable(); // Spring $ has CSRF enabled by default hence disabling the same

		// told that we need to put name here ROLE for Comparison as we are using
		// security 4

		http.authorizeRequests()

				.antMatchers("/emp/controller/addEmp**").access("hasRole('MSD_ADMIN')")
				.antMatchers("/emp/controller/updateEmp**").access("hasRole('MSD_ADMIN')")
				.antMatchers("/emp/controller/deleteEmp/**").access("hasRole('MSD_ADMIN')")
				.antMatchers("/emp/controller/getDetails**").access("hasRole('MSD_ADMIN') or hasRole('MSD_DBA') or hasRole('MSD_USER')")
				.antMatchers("/emp/controller/getDetailsById/**").access("hasRole('MSD_ADMIN') or hasRole('MSD_DBA')")
				.and().sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS).and().httpBasic()
				.realmName(MyBasicAuthenticationEntryPoint.REALM).authenticationEntryPoint(getBasicAuthEntryPoint());
	}

	@Bean
	public MyBasicAuthenticationEntryPoint getBasicAuthEntryPoint() {
		return new MyBasicAuthenticationEntryPoint();
	}

	public DriverManagerDataSource getSecurityDataSource() {
		DriverManagerDataSource dataSource = new DriverManagerDataSource();
		dataSource.setDriverClassName(driverName);
		dataSource.setUrl(securityUrl);
		dataSource.setUsername(userName);
		dataSource.setPassword(password);
		return dataSource;
	}

	@Autowired
	public void configureGlobal(AuthenticationManagerBuilder auth) throws Exception {
		auth.jdbcAuthentication().dataSource(getSecurityDataSource())
				.usersByUsernameQuery("select username,password, enabled from msd_users where username=?")
				.authoritiesByUsernameQuery("select username, role from msd_user_roles where username =?");
	}

	@Bean
	public static PropertySourcesPlaceholderConfigurer propertyConfigInDev() {
		return new PropertySourcesPlaceholderConfigurer();
	}
}

/**
 * 
 * authorizeRequests(): It allows restricted access. HTTP requests are
 * authorized before being served. antMatchers(): It matches the URL with given
 * pattern. access(): It checks if the USER has provided role. formLogin():
 * Enables form based authentication. loginPage(): It specifies the custom login
 * page URL. loginProcessingUrl(): It specifies the URL using which username and
 * password is validated. usernameParameter(): It specifies the field name to
 * enter user name which is used by spring security to validate. If not
 * specified then default is username. passwordParameter(): It specifies the
 * field name to enter password which is used by spring security to validate. If
 * not specified then default is password. defaultSuccessUrl(): It specifies the
 * default URL which is used by spring security after successful authentication.
 * logout(): It support the logout functionality in spring security application.
 * logoutUrl(): If defines the URL for logout. If CSRF protection is enabled,
 * logout request must be POST. logoutSuccessUrl(): It specifies the URL which
 * is used by spring security after successful logout.
 * 
 * configureGlobal(): It configures AuthenticationManager. Here we are using
 * in-memory authentication in our example.
 */