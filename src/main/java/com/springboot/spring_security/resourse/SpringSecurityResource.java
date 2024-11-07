package com.springboot.spring_security.resourse;

import org.springframework.web.bind.annotation.RestController;

import jakarta.servlet.http.HttpServletRequest;

import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;


@RestController
public class SpringSecurityResource {

		@GetMapping("/csrf")
		public CsrfToken retrieveCSRF(HttpServletRequest http) {
			return (CsrfToken) http.getAttribute("_csrf");
		}
		
}
