package security.security1.config.auth.oauth;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;
import security.security1.config.auth.PrincipalDetails;
import security.security1.config.auth.oauth.provider.FacebookUserInfo;
import security.security1.config.auth.oauth.provider.GoogleUserInfo;
import security.security1.config.auth.oauth.provider.NaverUserInfo;
import security.security1.config.auth.oauth.provider.OAuth2UserInfo;
import security.security1.model.User;
import security.security1.repository.UserRepository;

import java.util.Map;

@Service
public class PrincipalOauth2UserService extends DefaultOAuth2UserService {

    @Autowired
    private BCryptPasswordEncoder bCryptPasswordEncoder;

    @Autowired
    private UserRepository userRepository;

    //구글로 부터 받은 userRequest 데이터에 대한 후처리 되는 함수
    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        System.out.println("getClientRegistration :" + userRequest.getClientRegistration()); //registraionId로 어떤 OAuth로 로그인 했는지 확인가능
        System.out.println("getAccessToken :" + userRequest.getAccessToken());

        OAuth2User oAuth2User = super.loadUser(userRequest);
        //System.out.println("getAttributes :" + super.loadUser(userRequest).getAttributes());
        System.out.println("getAttributes :" + oAuth2User.getAttributes());

        //회원가입을 강제로 진행해 볼 예정
        OAuth2UserInfo oAuth2UserInfo = null;
        if (userRequest.getClientRegistration().getRegistrationId().equals("google")) {
            System.out.println("구글 로그인 요청");
            oAuth2UserInfo = new GoogleUserInfo(oAuth2User.getAttributes());
        } else if (userRequest.getClientRegistration().getRegistrationId().equals("facebook")) {
            System.out.println("페이스북 로그인 요청");
            oAuth2UserInfo = new FacebookUserInfo(oAuth2User.getAttributes());
        } else if (userRequest.getClientRegistration().getRegistrationId().equals("naver")) {
            System.out.println("네이버 로그인 요청");
            oAuth2UserInfo = new NaverUserInfo((Map<String, Object>) oAuth2User.getAttributes().get("response"));
        } else {
            System.out.println("우리는 구글과 페이스북만 지원해요 ㅎㅎ");
        }

        //String provider = userRequest.getClientRegistration().getRegistrationId(); // google
        String provider = oAuth2UserInfo.getProvider();
        //String providerId = oAuth2User.getAttribute("sub"); //getAttribute와 getAttributes는 다르다
        String providerId = oAuth2UserInfo.getProviderId();
        String username = provider + "_" + providerId; // ex) google_109742856218291042129;
        String password = bCryptPasswordEncoder.encode("겟인데어");
        //String password = "비밀번호";
        String email = oAuth2User.getAttribute("email");
        String role = "ROLE_USER";
        //구글 로그인 버튼 -> 로그인 요청 -> 로그인 완료 -> code 발급(OAuth2-Client로) -> 액세스토큰 발급
        //userRequest 정보 -> loadUser 함수 호출 -> loadUser로 구글 회원프로필 정보 획득

        User userEntity = userRepository.findByUsername(username);

        if(userEntity == null){
            System.out.println("로그인이 최초입니다.");
            userEntity = User.builder()
                    .username(username)
                    .password(password)
                    .email(email)
                    .role(role)
                    .provider(provider)
                    .providerId(providerId)
                    .build();
            userRepository.save(userEntity);
        }else {
            System.out.println("로그인을 이미 했기에 당신은 자동회원가입이 되어있습니다.");
        }
        //return super.loadUser(userRequest);
        return new PrincipalDetails(userEntity, oAuth2User.getAttributes()); // return 된 값이 어디로 갈까?
    }
}
