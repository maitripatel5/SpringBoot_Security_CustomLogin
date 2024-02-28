package com.demo.controllers;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.servlet.ModelAndView;

@Controller
public class SecurityUserController {

	@GetMapping("/login")
	public String login(Model model, String error, String logout) {
		System.out.println("Inside login API!");
		ModelAndView model2 = new ModelAndView("login");
		if (error != null)
			model.addAttribute("errorMsg", "Your username and password are invalid.");
		if (logout != null)
			model.addAttribute("msg", "You have been logged out successfully.");
		
		return "login";
	}

}
