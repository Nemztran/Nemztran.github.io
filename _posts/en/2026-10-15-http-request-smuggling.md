---
title: "Notes on HTTP Request Smuggling"
description: "Understanding HTTP Request Smuggling (CL.TE, TE.CL, TE.TE) and applying it to PortSwigger labs."
date: 2026-10-15 14:00:00 +0700
lang: en
categories: [Web Security, PortSwigger Labs]
tags: [http-request-smuggling, web-exploitation, portswigger, writeup]
toc: true
media_subpath: /assets/img/posts/2026-10-15-http-request-smuggling
math: true
pin: true
---

## I. What is HTTP Request Smuggling?

When I translated the name into Vietnamese, it came back as **smuggling HTTP requests** 🤔. Where does that name come from?

![image](start.png)

After looking into it, I found that the issue comes from a disagreement about how to process HTTP requests between a front-end server (a proxy, load balancer, and so on) and a back-end server. Each side interprets the same data differently. An attacker can **smuggle** a malicious HTTP request inside a legitimate one, causing the system to process requests incorrectly and creating further security issues.

Think of hiding prohibited goods inside ordinary cargo to get through an inspection. Here, the attacker hides a malicious request inside a seemingly harmless HTTP request and sends it to the server.

![HTTP Request Smuggling](1.png)

---

## II. How does HTTP Request Smuggling work?

- In modern web applications, users send requests to a front-end server, such as a reverse proxy or load balancer, which forwards them to one or more back-end servers. This architecture is increasingly common and is essential in some environments, including modern cloud applications.
- For efficiency and performance, the front end often forwards multiple HTTP requests over the same connection to the back end. Requests are sent consecutively, so the receiving server must determine where one request ends and the next begins.

![image](2.png)

- The front end and back end must agree on the **boundary** between requests. Otherwise, an attacker can send a request that the two sides interpret differently, with unintended consequences.
- Why not use a separate TCP connection for every request, as was common with HTTP/1.0? Wouldn't identifying the beginning and end of each request be easier?

![image](3.jpeg)

In theory, yes. In practice, opening a TCP connection and performing a three-way handshake for every request consumes considerable resources when thousands of requests are involved.
$\Rightarrow$ Reusing connections lets multiple requests share one TCP connection, but disagreements about message boundaries create the vulnerability discussed here.

The back end receives a stream of bytes. How does it know which bytes belong to **request A** and which belong to **request B**? That distinction is the **request boundary**.

Suppose the back end decodes the following bytes from a connection:

```http
POST /login HTTP/1.1
Host: example.com
Content-Length: 5

helloGET /home HTTP/1.1
Host: example.com
```

The back end must identify the boundary between the requests:

```text
┌──────────── Request 1 ────────────┐
POST /login HTTP/1.1
Host: example.com
Content-Length: 5

hello
└───────────────────────────────────┘

┌──────────── Request 2 ────────────┐
GET /home HTTP/1.1
Host: example.com
└───────────────────────────────────┘
```

- How does this become a vulnerability?

![image](4.png)

In the illustration above, the attacker makes the back end interpret part of a request sent to the front end as the beginning of the next request. That data is effectively prepended to the next request and can change how the server processes it.

---

## III. Where does the vulnerability come from?

Most HTTP Request Smuggling vulnerabilities arise because HTTP/1 offers two ways to determine the end of a request, through the **Content-Length** and **Transfer-Encoding** headers.

- **Content-Length** specifies the length of the message body in bytes:

```http
POST /search HTTP/1.1
Host: normal-website.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 11

q=smuggling
```

- **Transfer-Encoding** indicates the transfer coding applied to the message body. Here, we are interested in **chunked encoding**.
  - The initial `b` is the **chunk size** in hexadecimal.
  - It is followed by the **chunk data**.
  - A **zero-sized chunk** marks the end.

```http
POST /search HTTP/1.1
Host: normal-website.com
Content-Type: application/x-www-form-urlencoded
Transfer-Encoding: chunked

b
q=smuggling
0
```

- Having two methods for specifying a message's length can create conflicting interpretations if both appear together. HTTP/1 addresses this by requiring **Content-Length** to be ignored when **Transfer-Encoding** is present.
- Even so, when two or more servers process a request in sequence, their implementations may disagree:
  - Some servers do not support `Transfer-Encoding`.
  - Others support it but can be made to ignore it by obfuscating the header.

If the front end and back end handle `Transfer-Encoding` differently, they may disagree about the boundaries between consecutive requests, creating this vulnerability.

---

## IV. Performing an HTTP Request Smuggling attack

Basic **HTTP Request Smuggling** attacks put both `Content-Length` and `Transfer-Encoding` into the same HTTP/1 request and manipulate the **front end** and **back end** into interpreting it differently:

- **CL.TE**: the **front end** uses `Content-Length`; the **back end** uses `Transfer-Encoding`.
- **TE.CL**: the **front end** uses `Transfer-Encoding`; the **back end** uses `Content-Length`.
- **TE.TE**: both support `Transfer-Encoding`, but an obfuscated header makes one ignore it.

### 1. CL.TE vulnerabilities

Here, the front end uses **Content-Length**, while the back end uses **Transfer-Encoding**. A request smuggling payload looks like this:

```http
POST / HTTP/1.1
Host: vulnerable-website.com
Content-Length: 13
Transfer-Encoding: chunked

0

SMUGGLED
```

- The **front end** reads **Content-Length** and treats the body as 13 bytes, ending immediately after **SMUGGLED**. It forwards the entire request to the back end.
- The **back end** reads **Transfer-Encoding** and processes the body as **chunked**. The first chunk has a declared length of **0**, so the back end considers the request complete. The remaining **SMUGGLED** bytes are left unprocessed and become the beginning of the next request on the connection.

#### Lab: HTTP request smuggling, basic CL.TE vulnerability

* **Lab link:** [HTTP request smuggling, basic CL.TE vulnerability](https://portswigger.net/web-security/request-smuggling/lab-basic-cl-te)

![image](5.png)

The goal is to smuggle a request so that the next request processed by the back end uses the `GPOST` method. The front end only accepts `GET` and `POST`.

- Capture a request to the lab, remove unnecessary headers, and add **Content-Length** and **Transfer-Encoding** to identify the vulnerability type. After some investigation, I found a decision tree similar to those used by automated scanners:

![image](6.png)

- Following that tree, construct a probing payload:

![image](7.png)

After a delay, the back end returns a timeout:

![image](8.png)

This points to **CL.TE**. Looking more closely:

- With **Content-Length: 6**, a front end using that header forwards only through **xyz**, leaving out **X**.
- If the back end uses **Transfer-Encoding**, it receives:

![image](9.png)

The first chunk contains three bytes, **xyz**. However, chunked encoding requires a following `\r\n` and additional chunks, or a zero-sized terminating chunk. Since the front end does not forward those bytes, the back end keeps waiting until it **times out**.

![image](10.png)

- Having identified **CL.TE**, build the payload described in **IV.1**. This illustration shows the attack:

![image](11.png)

And the lab is solved 🤓:

![image](12.png)

---

### 2. TE.CL vulnerabilities

Here, the front end uses `Transfer-Encoding`, while the back end uses `Content-Length`. Consider this request:

```http
POST / HTTP/1.1
Host: vulnerable-website.com
Content-Length: 3
Transfer-Encoding: chunked

8
SMUGGLED
0
```

- The front end processes **Transfer-Encoding**, reading the body as **chunked**. The first chunk contains the eight-byte string **SMUGGLED**. A **zero-sized** chunk then terminates the request. The front end forwards the entire request to the back end.

> **Note:** Terminate the chunked body with two `\r\n` sequences immediately after the zero:
> ```text
> 0\r\n
> \r\n
> ```
{: .prompt-warning }

- The back end uses **Content-Length** and reads only **three bytes** of the body: **`8\r\n`**. The remaining bytes, beginning with **S**, are left over and become the start of the next request on the connection.

#### Lab: HTTP request smuggling, basic TE.CL vulnerability

* **Lab link:** [HTTP request smuggling, basic TE.CL vulnerability](https://portswigger.net/web-security/request-smuggling/lab-basic-te-cl)

![image](13.png)

The objective is the same as in the previous lab. Start with the decision tree to identify the vulnerability:

![image](14.png)

The first probe produces `400 Bad Request`:

![image](15.png)

The `{"error":"Invalid request"}` response suggests that the front end rejected the request. It probably processes **Transfer-Encoding**, since the body does not conform to chunked encoding. This narrows the possibilities to **TE.CL** or **TE.TE**. Send another probe:

![image](16.png)

The server times out. This indicates **TE.CL**, because the back end receives:

![image](17.png)

The back end expects six bytes according to **Content-Length**, but the current chunk provides only five. It waits for the final byte, rather like waiting for a reply from your crush, and eventually times out :<

![image](18.png)

Now construct a payload that makes the back end process `GPOST`. I put a request using that method inside a chunk. The request is 92 bytes long, whose hexadecimal representation is `5c`.

![image](19.png)

A zero-sized chunk follows. The back end initially reads only the first four bytes, **`5c\r\n`**, and treats the remainder as the following request.

**Why use Content-Length: 11?** A value of 10 or more works here, but 11 makes the effect easier to observe. The smuggled request body already contains ten bytes. With **Content-Length: 10**, the back end can process both requests from this one incoming message, solving the lab. However, the `"Unrecognized method GPOST"` response is not visible: the front end returns the response to the original POST, while the response to the smuggled GPOST is lost.

![image](20.png)

Using 11 makes the smuggled request consume one byte from the following request. A following `POST` becomes `OST`, which is not a recognized method. Send the request again and the lab completes with the expected result:

![image](21.png)

---

### 3. TE.TE vulnerabilities

Both servers support `Transfer-Encoding`, but **obfuscation** can make one of them ignore it. There are many possible variations:

```http
Transfer-Encoding: xchunked

Transfer-Encoding : chunked

Transfer-Encoding: chunked
Transfer-Encoding: x

Transfer-Encoding:[tab]chunked

[space]Transfer-Encoding: chunked

X: X[\n]Transfer-Encoding: chunked

Transfer-Encoding
: chunked
```

Each variation deviates slightly from the **HTTP** specification. Real implementations do not always follow the specification perfectly, so different systems tolerate different malformed headers.

To find **TE.TE**, identify a version of **Transfer-Encoding** that only one of the two servers processes. The resulting attack then follows either the CL.TE or TE.CL scenario above.

#### Lab: HTTP request smuggling, obfuscating the TE header

* **Lab link:** [HTTP request smuggling, obfuscating the TE header](https://portswigger.net/web-security/request-smuggling/lab-obfuscating-te-header)

![image](22.png)

The objective is the same as in the first two labs:

![image](23.png)

Use the decision tree again:

![image](24.png)

The front end rejects this request with `"invalid request"`, indicating that it processes **Transfer-Encoding**. Next, check whether the back end also supports it:

![image](25.png)

The timeout indicates that the back end also supports **Transfer-Encoding**, pointing to **TE.TE**. We now need to obfuscate the header so that only one server processes it. After plenty of attempts, I succeeded by adding another `Transfer-Encoding` header with an arbitrary value:

![image](26.png)

This payload makes the back end **time out**. The front end still processes **Transfer-Encoding**, while the back end falls back to **Content-Length**. The back end may be using the final header value, `x`, which it does not recognize as chunked encoding.

![image](27.png)

From here, use the payload for the **TE.CL** scenario:

![image](28.png)

---

### More practice

These two additional PortSwigger labs help reinforce the technique:

- [Confirming CL.TE via differential responses](https://portswigger.net/web-security/request-smuggling/finding/lab-confirming-cl-te-via-differential-responses)
- [Confirming TE.CL via differential responses](https://portswigger.net/web-security/request-smuggling/finding/lab-confirming-te-cl-via-differential-responses)
