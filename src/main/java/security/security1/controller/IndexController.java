package security.security1.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.annotation.Secured;
import org.springframework.security.access.prepost.PostAuthorize;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import security.security1.config.auth.PrincipalDetails;
import security.security1.model.User;
import security.security1.repository.UserRepository;

@Controller
public class IndexController {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private BCryptPasswordEncoder bCryptPasswordEncoder;

    @GetMapping("/test/login")
    @ResponseBody
    public String testLogin(
            Authentication authentication, // DI 의존성 주입
            // @AuthenticationPrincipal UserDetails userDetails
            @AuthenticationPrincipal PrincipalDetails userDetails){
        System.out.println("test/login ==============");

        PrincipalDetails principalDetails = (PrincipalDetails)authentication.getPrincipal();
        System.out.println("authentication : " + principalDetails.getUser());

        //System.out.println("userDetails :" + userDetails.getUsername());
        System.out.println("userDetails :" + userDetails.getUser());
        return "세션 정보 확인하기";
    }

    @GetMapping("/test/oauth/login")
    @ResponseBody
    public String testOauthLogin(
            Authentication authentication,
            @AuthenticationPrincipal OAuth2User oAuth) {// DI 의존성 주입
        System.out.println("test/oauth/login ==============");

        OAuth2User oAuth2User = (OAuth2User) authentication.getPrincipal();
        System.out.println("authentication : " + oAuth2User.getAttributes());

        //System.out.println("userDetails :" + userDetails.getUsername());
        //System.out.println("userDetails :" + userDetails.getUser());
        System.out.println("oauth2User : " + oAuth.getAttributes());
        return "세션 정보 확인하기";
    }

    @GetMapping({"","/"})
    public String index(){
        return "index";
    }

    @GetMapping("/user")
    @ResponseBody
    public String user(@AuthenticationPrincipal PrincipalDetails principalDetails){
        System.out.println("principalDetails : " + principalDetails.getUser() );
        return "user";
    }

    @GetMapping("/admin")
    @ResponseBody
    public String admin(){
        return "admin";
    }

    @GetMapping("/manager")
    @ResponseBody
    public String manager(){
        return "manager";
    }

    @GetMapping("/loginForm") //스프링 시큐리리티 해당 주소를 낚아챈다 - SecurityConfig 파일 생성 후 작동 안 함
    public String loginForm(){
        return "loginForm";
    }

    @GetMapping("/joinForm")
    public String joinForm(){
        return "joinForm";
    }

    @PostMapping ("/join")
    public String join(User user){
        System.out.println(user);
        user.setRole("ROLE_USER");

        String rawPassword = user.getPassword();
        String encPassword = bCryptPasswordEncoder.encode(rawPassword);
        user.setPassword(encPassword);
        userRepository.save(user); // 회원가입이 잘 됨 but, 이렇게 하면 시큐리티로 로그인 할 수가 없음. 이유는 패스워드 암호화가 안 되었기 때문
        return "redirect:/loginForm"; // redirect를 붙이면 loginForm이라는 함수를 호출해준다
    }

    @Secured("ROLE_ADMIN")
    @GetMapping("/info")
    @ResponseBody
    public String info(){
        return "개인정보";
    }

    @PreAuthorize("hasRole('ROLE_MANAGER') or hasRole('ROLE_ADMIN')")
    @GetMapping("/data")
    @ResponseBody
    public String data(){
        return "데이터 정보";
    }

}
