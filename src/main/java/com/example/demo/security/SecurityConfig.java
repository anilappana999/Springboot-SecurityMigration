package com.example.demo.security;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

@Configuration
public class SecurityConfig extends WebSecurityConfigurerAdapter {

//	@Override
//	public void configure(WebSecurity web) throws Exception {
//		
//	}

	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {

		auth.inMemoryAuthentication().withUser("root").password("{noop}root").roles("ADMIN");
		auth.inMemoryAuthentication().withUser("anil").password("{noop}anil").roles("USER");

	}

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http.csrf().disable();
		http.authorizeRequests().antMatchers("/demo/**").hasAnyRole("ADMIN").anyRequest().fullyAuthenticated().and()
				.formLogin().permitAll().and().logout().permitAll();
		// http.authorizeRequests().antMatchers("/**").hasRole("USER").and().httpBasic();
	}

//	@SuppressWarnings("deprecation")
//	@Bean
//	public static NoOpPasswordEncoder passwordEncoder() {
//		return (NoOpPasswordEncoder) NoOpPasswordEncoder.getInstance();
//	}

}
