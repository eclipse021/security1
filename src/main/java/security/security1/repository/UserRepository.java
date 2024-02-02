package security.security1.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import security.security1.model.User;

//CRUD 함수를 JpaRepository가 들고 있음
//@Repository가 없어도 IoC가 된다. 그 이유는 JpaRepository를 상속했기 때문
public interface UserRepository extends JpaRepository<User, Integer> {

    //public User findByUserName(String username);
    public User findByUsername(String username);
}
