package com.springboot.spring_security.resourse;

import java.util.List;

import org.apache.commons.logging.LogFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.access.annotation.Secured;
import org.springframework.security.access.prepost.PostAuthorize;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;


@RestController
public class TodoResource {
	
	
	private Logger logger = LoggerFactory.getLogger(getClass());

		private static final List<ToDo> ToDoList = List.of(new ToDo("sri", "dev"),
			new ToDo("leo", "test"));

		@GetMapping("/todo")
		public List<ToDo> helloWorld() {
			return ToDoList;
		}
		
		@GetMapping("/users/{username}/todo")
		@PreAuthorize("hasRole('USER') and #username == authentication.name")
		@PostAuthorize("returnObject.name=='sri'")
		@Secured({"ROLE_ADMIN","ROLE_USER"})
		public ToDo retriveUser(@PathVariable String username) {
			return ToDoList.get(0);
		}
		
		@PostMapping("/users/{username}/todo")
		public void createUser(@PathVariable String username, 
				@RequestBody ToDo todo) {
			logger.info("create {} for {}", todo, username);
		}
		
}

record ToDo(String name, String desc) {}
