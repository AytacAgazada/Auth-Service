
#### 1\. **Yeni Bir Xidmət Sinfi: `StateFinVerificationService.java`**

Bu sinif, FIN kodunu dövlət verilənlər bazası (bir API vasitəsilə) ilə yoxlamaqdan məsul olacaq.

```java
// package com.example.authservice.service; (Veya başka uygun bir paket)

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate; // Eğer REST API kullanıyorsanız
// import org.springframework.web.reactive.function.client.WebClient; // Eğer asenkron REST API kullanıyorsanız

@Service
public class StateFinVerificationService {

    private final RestTemplate restTemplate; // RestTemplate'i veya WebClient'ı kullanın

    // Bu URL'yi application.properties dosyanızda tanımlamanız gerekecek
    // Örneğin: state.fin.verification.url=https://your-state-api.gov/verify-fin
    @Value("${state.fin.verification.url}")
    private String stateFinVerificationUrl;

    // RestTemplate veya WebClient için bir constructor injection yapmalısınız
    public StateFinVerificationService(RestTemplate restTemplate) {
        this.restTemplate = restTemplate;
    }

    /**
     * FIN kodunun dövlət verilənlər bazasında mövcudluğunu və etibarlılığını yoxlayır.
     * Bu metodun daxilində dövlət tərəfindən təmin edilmiş xarici API çağırışı edilməlidir.
     *
     * @param finCode Vətəndaşın FIN kodu
     * @return Əgər FIN kodu dövlət məlumatları ilə uyğun gəlirsə true, əks halda false.
     * @throws RuntimeException Xarici API ilə əlaqə qurularkən və ya cavab işlənərkən xəta baş verərsə.
     */
    public boolean verifyFinAgainstStateDatabase(String finCode) {
        try {
            // --- Buraya dövlət API-nə müraciət kodunu yazın ---
            // Bu kısım, kullandığınız dövlət API'sinin spesifikasyonuna göre değişir.
            // Örnek olarak, bir REST API çağrısı yapalım:

            // Eğer API bir GET isteği bekliyorsa:
            // String apiUrl = stateFinVerificationUrl + "?fin=" + finCode;
            // ResponseEntity<String> response = restTemplate.getForEntity(apiUrl, String.class);
            // return response.getStatusCode().is2xxSuccessful() && "VALID".equalsIgnoreCase(response.getBody());

            // Eğer API bir POST isteği ve JSON body bekliyorsa:
            /*
            Map<String, String> requestBody = new HashMap<>();
            requestBody.put("fin", finCode);
            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_JSON);
            HttpEntity<Map<String, String>> requestEntity = new HttpEntity<>(requestBody, headers);
            ResponseEntity<FinVerificationResponse> response = restTemplate.postForEntity(stateFinVerificationUrl, requestEntity, FinVerificationResponse.class);
            return response.getStatusCode().is2xxSuccessful() && response.getBody() != null && response.getBody().isValid();
            */

            // Şimdilik sadece bir yer tutucu (placeholder) olarak:
            // Gerçek bir API entegrasyonu olmadığından, her zaman true döndürmeyelim.
            // Örneğin, "1234567" FIN kodunun geçerli olduğunu varsayalım.
            if ("1234567".equals(finCode)) {
                System.out.println("FIN kodu dövlət bazasında tapıldı: " + finCode);
                return true;
            } else {
                System.out.println("FIN kodu dövlət bazasında tapılmadı: " + finCode);
                return false;
            }

        } catch (Exception e) {
            // Xarici servis çağırısında hər hansı bir xəta yaranarsa
            log.error("FIN kodunu dövlət bazasında yoxlayarkən xəta baş verdi: {}", e.getMessage(), e);
            // Güvenlik açısından, dış servisteki bir hata durumunda varsayılan olarak doğrulamayı başarısız saymak daha güvenlidir.
            throw new RuntimeException("Dövlət FIN doğrulama xidməti ilə əlaqə qurularkən xəta baş verdi.", e);
        }
    }

    // Eğer REST API'nin cevabı karmaşık bir JSON nesnesi ise,
    // FinVerificationResponse gibi bir DTO sınıfı tanımlamanız gerekebilir.
    /*
    @Data // Lombok
    public static class FinVerificationResponse {
        private boolean valid;
        private String message;
        // Diğer alanlar (Ad, Soyad vb.)
    }
    */
}
```

-----

#### 2\. **`AuthService.java` Sinfi üçün Dəyişikliklər**

`StateFinVerificationService`'i inject edin və `authenticateUser` metodunu FIN kodunu da yoxlayacaq şəkildə dəyişdirin.

```java
// package com.example.authservice.service;

// ... (Mevcut importlarınız) ...

import org.springframework.security.authentication.BadCredentialsException; // Bu importu əlavə edin

// ... (Mevcut sınıf tanımı) ...

public class AuthService {

    // ... (Mevcut final private alanlarınız) ...
    private final StateFinVerificationService stateFinVerificationService; // Yeni servis alanını əlavə edin

    @Value("${otp.expiration-seconds}")
    private long otpExpirationSeconds;

    // Konstruktora StateFinVerificationService-i əlavə edin
    public AuthService(UserRepository userRepository, PasswordEncoder passwordEncoder, UserMapper userMapper,
                       AuthenticationManager authenticationManager, JwtUtils jwtUtils,
                       RefreshTokenRepository refreshTokenRepository, EmailService emailService,
                       WhatsAppService whatsAppService,
                       ConfirmationTokenRepository confirmationTokenRepository,
                       StateFinVerificationService stateFinVerificationService) { // Yeni parametre
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.userMapper = userMapper;
        this.authenticationManager = authenticationManager;
        this.jwtUtils = jwtUtils;
        this.refreshTokenRepository = refreshTokenRepository;
        this.emailService = emailService;
        this.whatsAppService = whatsAppService;
        this.confirmationTokenRepository = confirmationTokenRepository;
        this.stateFinVerificationService = stateFinVerificationService; // Yeni servisi set edin
    }

    // ... (registerUser, sendOtp, verifyOtp, resetPassword metodları dəyişmir) ...


    /**
     * İstifadəçinin identifikasiya məlumatları (FIN, username, email) və şifrə ilə autentifikasiya edir.
     * Əlavə olaraq, girişdə təqdim olunan FIN kodunu dövlət verilənlər bazasında yoxlayır.
     * JWT Access Token və Refresh Token qaytarır.
     *
     * @param loginRequest Login məlumatları (identifier, password, **finCode**)
     * @param request HTTP request obyekti (User-Agent və IP almaq üçün)
     * @return Autentifikasiya cavabı (JWT tokenlər və istifadəçi məlumatları)
     * @throws InvalidCredentialsException Əgər identifikasiya məlumatları, şifrə və ya FIN kodu yanlışdırsa.
     * @throws RuntimeException Dövlət FIN doğrulama xidməti ilə bağlı problemlər yaranarsa.
     */
    @Transactional
    public AuthResponse authenticateUser(LoginRequest loginRequest, HttpServletRequest request) {
        // Mövcud findUserByIdentifier metodu FIN, email və ya username ilə axtarış aparır.
        // Bu o deməkdir ki, loginRequest.getIdentifier() FIN də ola bilər.
        // Fərz edirik ki, əgər loginRequest.getIdentifier() FIN-dirsə, və istifadəçi FIN-i ilə daxil olmaq istəyirsə,
        // bu zaman dövlət yoxlamasını tətbiq edirik.

        User user = findUserByIdentifier(loginRequest.getIdentifier());

        if (!user.isEnabled()) {
            throw new InvalidCredentialsException("Hesab aktiv deyil. Zəhmət olmasa hesabınızı təsdiqləyin.");
        }

        // Parol yoxlaması
        try {
            authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(loginRequest.getIdentifier(), loginRequest.getPassword()));
        } catch (BadCredentialsException e) {
            throw new InvalidCredentialsException("Yanlış istifadəçi adı, FIN, email və ya şifrə.");
        }

        // --- ƏLAVƏ EDİLƏN FIN KODU DOĞRULAMA HİSSƏSİ ---
        // Əgər login requestdə bir FIN kodu verilmişsə VƏ bu istifadəçi FIN əsasında tapılıbsa
        // (yəni user.getFin() mövcuddursa), o zaman dövlət yoxlamasını edirik.
        // Yoxsa, məsələn, istifadəçi email ilə daxil olarsa və FIN kodu verməzsə bu yoxlamanı atlayırıq.
        if (loginRequest.getFin() != null && !loginRequest.getFin().trim().isEmpty()) {
            // Daxili sistemdə tapılan user-in FIN kodu ilə login requestdə gələn FIN kodu eyni olmalıdır.
            if (!user.getFin().equalsIgnoreCase(loginRequest.getFin())) {
                throw new InvalidCredentialsException("Daxil edilən FIN kodu istifadəçi ilə uyğun gəlmir.");
            }

            // Dövlət FIN doğrulama servisini çağırırıq
            boolean isFinValidInStateDb = stateFinVerificationService.verifyFinAgainstStateDatabase(loginRequest.getFin());
            if (!isFinValidInStateDb) {
                // Eğer FIN kodu devlet veri tabanında doğrulanamazsa
                throw new InvalidCredentialsException("FIN kodu dövlət verilənlər bazasında təsdiqlənmədi.");
            }
        }
        // --- FIN KODU DOĞRULAMA HİSSƏSİNİN SONU ---


        SecurityContextHolder.getContext().setAuthentication(authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(loginRequest.getIdentifier(), loginRequest.getPassword())));


        UserDetailsImpl userDetails = (UserDetailsImpl) SecurityContextHolder.getContext().getAuthentication().getPrincipal();

        String jwt = jwtUtils.generateTokenFromUsername(userDetails.getUsername()); // userDetails.getUsername() burada FIN olmalıdır

        String userAgent = request.getHeader("User-Agent");
        String ipAddress = request.getRemoteAddr();

        RefreshToken refreshToken = refreshTokenRepository.findByUserAndUserAgent(user, userAgent)
                .map(existingToken -> {
                    existingToken.setExpiryDate(Instant.now().plusMillis(jwtUtils.getRefreshTokenExpirationMs()));
                    existingToken.setIpAddress(ipAddress);
                    return refreshTokenRepository.save(existingToken);
                })
                .orElseGet(() -> jwtUtils.createRefreshToken(user, userAgent, ipAddress));

        List<String> roles = userDetails.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.toList());

        return new AuthResponse(
                jwt,
                refreshToken.getToken(),
                userDetails.getId(),
                userDetails.getActualUsername(),
                userDetails.getUsername(), // FIN
                userDetails.getEmail(),
                userDetails.getPhone(),
                roles
        );
    }

    // ... (refreshAccessToken, logoutUser, findUserByIdentifier, generateOtpCode metodları dəyişmir) ...
}
```

-----

#### 3\. **`LoginRequest.java` DTO Sinfi üçün Dəyişikliklər**

`fin` sahəsini `LoginRequest` sinfinə əlavə edin.

```java
// package com.example.authservice.model.dto;

import jakarta.validation.constraints.NotBlank; // Eğer fin alanı da zorunlu olacaksa
import lombok.Data;

@Data
public class LoginRequest {
    @NotBlank(message = "Identifier (username, email, or FIN) cannot be blank.")
    private String identifier; // FIN, username veya email olabilir

    @NotBlank(message = "Password cannot be blank.")
    private String password;

    private String fin; // <-- BU ALANI EKLİYORUZ. Kullanıcı giriş yaparken FIN kodunu da gönderebilir.
}
```

-----

#### 4\. **`application.properties` Faylına Əlavə**

`StateFinVerificationService`'in istifadə edəcəyi dövlət API URL-ni əlavə edin.

```properties
# ... (Mevcut property'leriniz) ...

# Dövlət FIN doğrulama servisi üçün API URL-i
state.fin.verification.url=https://your-state-api.gov/verify-fin-endpoint # Bu URL-i real URL ilə əvəz edin
```

-----

### **Əlavə Mülahizələr**

  * **`RestTemplate` Konfiqurasiyası**: Əgər `RestTemplate` (və ya `WebClient`) istifadə edəcəksinizsə, onu Spring kontekstində bir `Bean` kimi təyin etməlisiniz. Bu adətən `SecurityConfig` kimi bir konfiqurasiya sinfində edilə bilər.

    ```java
    // SecurityConfig.java və ya ayrı bir RestTemplateConfig.java
    import org.springframework.context.annotation.Bean;
    import org.springframework.context.annotation.Configuration;
    import org.springframework.web.client.RestTemplate;

    @Configuration
    public class AppConfig { // Veya mevcut SecurityConfig sınıfınızın içine
        @Bean
        public RestTemplate restTemplate() {
            return new RestTemplate();
        }
    }
    ```

  * **Xəta İdarəetməsi**: Dövlət API-si ilə əlaqə qurarkən şəbəkə xətaları, zaman aşımı (timeout) və ya API-dən gələn xəta cavabları (`4xx`, `5xx`) ola bilər. `StateFinVerificationService` içərisində `try-catch` bloklarını genişləndirərək bu halları daha dəqiq idarə etməlisiniz. Məsələn, `RuntimeException` yerinə daha spesifik bir exception (məsələn, `StateServiceUnavailableException`) ata bilərsiniz.

  * **FIN Kodu Nə Zaman Yoxlanılmalıdır?**: Mənim yuxarıdakı nümunəm `authenticateUser` metodunda, istifadəçi **loginRequest.getFin()** vasitəsilə bir FIN kodu göndərirsə, bu yoxlamanı edir. Əgər istifadəçinin hər girişində (FIN, email və ya username ilə daxil olmasından asılı olmayaraq) onun FIN-i dövlət bazasında yoxlanılmalıdursa, o zaman `User` obyektindən `fin` alanını alıb həmin kodu hər zaman yoxlamanız lazımdır.

      * Yəni, `loginRequest.getFin()` yoxlamaq əvəzinə, hər zaman `user.getFin()` yoxlamaq daha doğru ola bilər. Lakin bu halda `User` obyektində mütləq FIN kodunun olması tələb olunacaq. Hazırda `user.getUsername()` kimi davranan `FIN` sahəsi olduğuna görə bu daha məntiqli görünür.

    <!-- end list -->

    ```java
    // AuthService.java içinde değiştirilmiş FIN doğrulama mantığı
    // Eğer her authentication'da FIN'in devletten doğrulanması gerekiyorsa
    if (user.getFin() != null && !user.getFin().trim().isEmpty()) {
        boolean isFinValidInStateDb = stateFinVerificationService.verifyFinAgainstStateDatabase(user.getFin());
        if (!isFinValidInStateDb) {
            throw new InvalidCredentialsException("Hesabınızla əlaqəli FIN kodu dövlət verilənlər bazasında təsdiqlənmədi.");
        }
    } else {
        // Eğer kullanıcının FIN'i yoksa ve devlet doğrulama zorunluysa, burada hata fırlatılabilir.
        // Ya da FIN'i olmayan kullanıcıların devlet doğrulamasına tabi tutulmadığı varsayılır.
    }
    ```

--------------------------------------------------------------
Təbii ki, tamamilə başa düşürəm! Hər istəyən dövlətin vətəndaş datasına birbaşa inteqrasiya edə bilməz. Məqsəd, **"necə olur"** sualına cavab vermək və belə bir ssenarinin texniki olaraq necə işlədiyini göstərməkdir, real dünya inteqrasiyasının çətinliklərinə baxmayaraq.

Əvvəlki cavablarda verdiyim kod nümunələri, bu "necə olur" sualına cavab vermək üçün bir sənəd təqdim edir. Yəni, bir **dövlət API-si mövcud olsaydı** və sizə ona çıxış icazəsi verilsəydi, sisteminizin həmin API ilə necə əlaqə quracağını göstərirdi.

---

### **Dövlət FIN Doğrulaması "Necə Olur" - Texniki Baxış**

FIN kodunun dövlət verilənlər bazasında yoxlanılması prosesi aşağıdakı əsas komponentlər vasitəsilə həyata keçirilir:

---

### 1. **Dövlət Tərəfindən Təmin Edilən API/Xidmət**

Bu, FIN kodunu yoxlamaq üçün lazım olan ən fundamental hissədir. Dövlət qurumu tərəfindən idarə olunan bir API (Application Programming Interface) və ya veb xidmət təmin edilməlidir. Bu API, adətən, yüksək təhlükəsizlik protokolları (məsələn, **OAuth2**, **API Keys**, **Rəqəmsal Sertifikatlar**) ilə qorunur və yalnız icazə verilmiş tətbiqlər ona daxil ola bilər.

* **RESTful API:** Ən çox yayılmış formatdır. Siz `HTTP POST` və ya `GET` sorğusu ilə FIN kodunu (və bəlkə də digər identifikasiya məlumatlarını) göndərirsiniz, API isə sizə JSON formatında bir cavab qaytarır (məsələn, FIN kodunun etibarlı olub-olmaması, adı, soyadı, və s.).
* **SOAP Veb Xidməti:** Bəzi köhnə sistemlərdə istifadə olunur. XML əsaslı sorğular və cavablar vasitəsilə ünsiyyət qurulur.
* **Müəyyən Protokollar:** Bəzi hallarda, daha xüsusi və təhlükəsizlik yönümlü protokollar (məsələn, X-Road kimi xidmət şəbəkələri) istifadə oluna bilər.

---

### 2. **Sizin Auth Servisinizdəki İnteqrasiya Komponenti (`StateFinVerificationService`)**

Sizin **AuthService**-niz birbaşa dövlət verilənlər bazasına qoşulmur. Əvəzində, dövlətin təmin etdiyi **API-yə müraciət edən** bir aralıq xidmətiniz olur. Əvvəlki nümunələrdə bu rolu **`StateFinVerificationService`** oynayır.

* Bu servis, dövlət API-si ilə əlaqə qurmaq üçün **`RestTemplate`** (Spring-də HTTP sorğuları üçün) və ya **`WebClient`** (daha müasir, reaktiv HTTP klient) kimi alətlərdən istifadə edir.
* O, sizin tətbiqinizdən gələn FIN kodunu qəbul edir.
* Dövlət API-sinin tələb etdiyi formata uyğun bir HTTP sorğusu yaradır (başlıqlar, sorğu gövdəsi, autentifikasiya məlumatları ilə birlikdə).
* Sorğuyu dövlət API-sinə göndərir və cavabı gözləyir.
* Gələn cavabı analiz edir (məsələn, cavabın status kodu `200 OK` dır, JSON gövdəsində `isValid: true` varmi, və s.).
* Yoxlamanın nəticəsini (məsələn, `true` və ya `false`) sizin `AuthService`-nizə qaytarır.
* Əlaqə problemləri və ya dövlət API-sindən gələn xətaları idarə edir.

---

### 3. **`AuthService` İçərisindəki Doğrulama Məntiqi**

Sizin **`AuthService`** içərisindəki `authenticateUser` metodu bu **`StateFinVerificationService`**-i çağırır.

* İstifadəçi daxili sisteminizdə **username/FIN/email** və **parol** ilə doğrulanır.
* **Bu daxili doğrulama uğurlu olduqdan sonra**, `AuthService` istifadəçinin təqdim etdiyi FIN kodunu (`loginRequest.getFin()` vasitəsilə) və ya istifadəçinin daxili məlumatlarında saxlanılan FIN kodunu `stateFinVerificationService.verifyFinAgainstStateDatabase()` metoduna göndərir.
* Əgər `stateFinVerificationService` `true` qaytararsa, bu, FIN kodunun dövlət səviyyəsində də təsdiqləndiyi deməkdir və istifadəçiyə JWT token verilir.
* Əks halda (`false` qaytararsa), giriş rədd edilir və müvafiq xəta mesajı qaytarılır.

---

### **Vizual Nümunə (Necə İşləyir)**

1.  **İstifadəçi:** "Mənim FIN-im: 1234567, Parolum: Gizli123"
2.  **Sizin Tətbiqiniz (Frontend):** Bu məlumatları `POST /api/auth/login` endpointinə göndərir.
3.  **Sizin `AuthController`:** `LoginRequest` obyektini alır və `authService.authenticateUser()` metodunu çağırır.
4.  **Sizin `AuthService`:**
    * Daxili verilənlər bazasında `User` obyektini tapır (FIN və parol yoxlaması).
    * `stateFinVerificationService.verifyFinAgainstStateDatabase("1234567")` metodunu çağırır.
5.  **Sizin `StateFinVerificationService`:**
    * Dövlət API-sinin URL-inə (məsələn, `https://state-api.gov/verify-fin`) HTTP sorğusu göndərir.
    * (Daxili olaraq) Dövlət API-si öz daxili, məxfi dövlət verilənlər bazası ilə əlaqə qurur, FIN kodunu yoxlayır.
    * Dövlət API-si cavab olaraq sizin `StateFinVerificationService`-ə bildirir ki, "1234567" FIN kodu etibarlıdır / etibarlı deyil.
6.  **Sizin `StateFinVerificationService`:** Cavabı `AuthService`-ə qaytarır.
7.  **Sizin `AuthService` (davamy):**
    * Əgər FIN kodu dövlət tərəfindən təsdiqlənibsə, JWT token yaradır.
    * Əks halda, girişə icazə vermir.
8.  **Sizin `AuthController`:** Cavabı istifadəçiyə (Frontendə) qaytarır (token və ya xəta).

---

Bu şəkildə, siz birbaşa dövlət bazasına daxil olmadan, dövlətin təqdim etdiyi **xidmət vasitəsilə** FIN kodunun doğruluğunu təsdiqləyə bilərsiniz. Məhz bu "aralıq xidmət" modeli, sizin məqsədinizi texniki olaraq necə reallaşdıracağınızı göstərir.

