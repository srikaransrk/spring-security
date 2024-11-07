package com.springboot.spring_security.resourse;

import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;


@RestController
public class HelloWorldResource {

		@GetMapping("/hello-world")
		public String helloWorld() {
			return "Hello Spring Security";
		}
		
}
