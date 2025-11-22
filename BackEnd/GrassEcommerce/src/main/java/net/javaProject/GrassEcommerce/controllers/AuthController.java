package net.javaProject.GrassEcommerce.controllers;

import jakarta.validation.Valid;
import net.javaProject.GrassEcommerce.models.ERole;
import net.javaProject.GrassEcommerce.models.Role;
import net.javaProject.GrassEcommerce.models.User;
import net.javaProject.GrassEcommerce.payload.request.LoginRequest;
import net.javaProject.GrassEcommerce.payload.request.SignUpRequest;
import net.javaProject.GrassEcommerce.payload.response.JwtResponse;
import net.javaProject.GrassEcommerce.payload.response.MessageResponse;
import net.javaProject.GrassEcommerce.respository.RoleRepository;
import net.javaProject.GrassEcommerce.respository.UserRepository;
import net.javaProject.GrassEcommerce.security.jwt.JwtUtils;
import net.javaProject.GrassEcommerce.security.services.UserDetailsImpl;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

@CrossOrigin(origins = "*", maxAge = 3600)
@RestController
@RequestMapping("/api/auth")
public class AuthController {
    @Autowired
    AuthenticationManager authenticationManager;

    @Autowired
    UserRepository userRepository;

    @Autowired
    RoleRepository roleRepository;

    @Autowired
    PasswordEncoder encoder;

    @Autowired
    JwtUtils jwtUtils;

    @PostMapping("/signin")
    public ResponseEntity<?> authentication(@Valid@RequestBody
    LoginRequest loginRequest){
        Authentication authentication = authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(loginRequest.getUsername(), loginRequest.getPassword()));

        SecurityContextHolder.getContext().setAuthentication(authentication);
        String jwt = jwtUtils.generateJwtToken(authentication);

        UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();
        List<String> roles = userDetails.getAuthorities().stream().map(item -> item.getAuthority()).collect(Collectors.toUnmodifiableList());

        return ResponseEntity
                .ok(new JwtResponse(jwt, userDetails.getId(), userDetails.getUsername(), userDetails.getEmail(), roles));
    }

    @PostMapping("/signup")
    public ResponseEntity<?> registerUser(@Valid@RequestBody SignUpRequest signUpRequest){
        if(userRepository.existsByUsername(signUpRequest.getUsername())){
            return ResponseEntity.badRequest().body(new MessageResponse("Error: Username already taken"));
        }

        if(userRepository.existsByEmail(signUpRequest.getEmail())){
            return ResponseEntity.badRequest().body(new MessageResponse("Error: Email already taken"));
        }

        User user = new User(signUpRequest.getUsername(), signUpRequest.getEmail(), encoder.encode(signUpRequest.getPassword()));

        Set<String> strRoles = signUpRequest.getRole();
        Set<Role> roles = new HashSet<>();

        if(strRoles == null){
            Role userRole = roleRepository.findByName(ERole.ROLE_USER)
                    .orElseThrow(() -> new RuntimeException("Error: Role not Found. "));
            roles.add(userRole);
        }else{
            strRoles.forEach(role -> {
                switch (role) {
                    case "admin":
                        Role adminRole = roleRepository.findByName(ERole.ROLE_ADMIN)
                                .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
                        roles.add(adminRole);

                        break;
                    case "mod":
                        Role modRole = roleRepository.findByName(ERole.ROLE_MODERATOR)
                                .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
                        roles.add(modRole);

                        break;
                    default:
                        Role userRole = roleRepository.findByName(ERole.ROLE_USER)
                                .orElseThrow(() ->  new RuntimeException("Error: Role is not found."));
                        roles.add(userRole);
                }
            });
        }

        user.setRoles(roles);
        userRepository.save(user);

        return ResponseEntity.ok(new MessageResponse("User Registered Succesfully"));
    }
}
