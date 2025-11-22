package net.javaProject.GrassEcommerce.respository;

import net.javaProject.GrassEcommerce.models.ERole;
import net.javaProject.GrassEcommerce.models.Role;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface RoleRepository extends JpaRepository<Role, Long> {
    Optional <Role> findByName(ERole name);
}
