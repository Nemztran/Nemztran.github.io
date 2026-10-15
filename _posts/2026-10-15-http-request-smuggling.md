---
title: "HTTP Request Smuggling: Lý thuyết và Thực hành PortSwigger Labs"
description: "Tìm hiểu bản chất lỗ hổng HTTP Request Smuggling (CL.TE, TE.CL, TE.TE) và hướng dẫn giải chi tiết các bài lab trên PortSwigger."
date: 2026-10-15 14:00:00 +0700
categories: [Web Security, PortSwigger Labs]
tags: [http-request-smuggling, web-exploitation, portswigger, writeup]
toc: true
math: true
pin: true
---

## I. HTTP Request Smuggling là gì?

Khi mình gg dịch kết quả trả về là **Buôn lậu HTTP Request** 🤔. Vậy cái tên này bắt nguồn từ đâu?

![image](https://hackmd.io/_uploads/rko1PC4Fzg.png)

Sau khi nghiên cứu về lỗ hổng này thì đó là do sự bất đồng bộ khi xử lí HTTP Request giữa front-end server (proxy, load balancer, ...) và back-end server, kiểu như mỗi bên hiểu theo 1 cách khác nhau ấy. Nó khá là nguy hiểm bởi attacker có thể tuồn **(smuggle)** một HTTP request độc hại ẩn trong một request hợp lệ khiến hệ thống xử lý sai lệch dẫn đến nhiều vấn đề khác.

Nó gọi là buôn lậu **(smuggling)** giống như kiểu giấu chất cấm trong hàng hóa để qua cửa kiểm tra chẳng hạn, thì ở đây là nhúng request độc hại vào trong 1 HTTP request trông có vẻ vô hại rồi gửi đến server xử lý.

![image](https://hackmd.io/_uploads/SyePja4Yzx.png)

---

## II. HTTP Request Smuggling diễn ra như thế nào?

- Trong các ứng dụng web hiện nay, users sẽ gửi request đến front-end server (có thể là reverse proxy, hoặc load balancer), rồi từ đó lại chuyển tiếp đến một hoặc một vài back-end servers. Kiểu kiến trúc này ngày càng trở nên phổ biến, và trong một số trường hợp là không thể không dùng đến như các ứng dụng hiện đại chạy trên cloud.
- Khi front-end server chuyển tiếp HTTP requests đến back-end server nó thường gửi nhiều request trên cùng một kết nối tới back-end, vì cách này mang lại hiệu quả và hiệu năng cao hơn. Giao thức này khá đơn giản: các HTTP request được gửi liên tiếp nhau, và phía server nhận cần phải xác định request này kết thúc ở đâu và request tiếp theo bắt đầu từ đâu.

![image](https://hackmd.io/_uploads/H1z_ApVtfg.png)

- Trong tình huống này, điều quan trọng là front-end và back-end phải thống nhất với nhau về **boundary** giữa các request. Nếu không thì attacker có thể gửi một request khiến front-end và back-end hiểu theo những cách khác nhau dẫn đến hậu quả ko mong muốn.
- Có 1 câu hỏi đặt ra là: Tại sao ko dùng 1 TCP connection cho 1 request (giao thức HTTP/1.0) thì việc xác định điểm bắt đầu và kết thúc của một request ko phải dễ dàng hơn sao?

![images](https://hackmd.io/_uploads/Sk1AYaEYfe.jpg)

Câu trả lời là: về mặt lí thuyết thì nó sẽ dễ dàng hơn, tuy nhiên để gửi một request đến back-end server, cần phải tạo kết nối TCP, bắt tay 3 bước các kiểu mới gửi được request mà điều này trong thực tế tốn rất nhiều tài nguyên khi có hàng nghìn request gửi đến.
$\Rightarrow$ Người ta đã nghĩ ra cách là tái sử dụng connection, nghĩa là gửi đồng thời nhiều request trên cùng 1 TCP connection luôn và cái giá phải trả là lỗ hổng đang bàn đây.

Khi nhận được request thì phía back-end chỉ nhận được chuỗi các bytes, câu hỏi đặt ra tiếp là: Làm thế nào để nó biết được byte nào là của **request A**, byte nào của **request B** $\rightarrow$ đó chính là **request boundary**.

Giả sử phía backend sau khi nhận được chuỗi các byte của 1 connection và giải mã được:

```http
POST /login HTTP/1.1
Host: example.com
Content-Length: 5

helloGET /home HTTP/1.1
Host: example.com
```

Nhiệm vụ của back-end là phải biết được boundary giữa các request:

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

- Vậy lỗ hổng này diễn ra như nào?

![image](https://hackmd.io/_uploads/rk7bkAEFfl.png)

Ví dụ như trên hình, attacker có thể khiến một phần request gửi tới front-end được back-end hiểu là phần bắt đầu của request tiếp theo. Dễ hiểu hơn là phần đó thực tế được đặt lên trước request tiếp theo, và nó có thể can thiệp vào cách server xử lý request đó.

---

## III. Lỗ hổng này bắt nguồn từ đâu?

Hầu hết các lỗ hổng HTTP Request Smuggling phát sinh do phương thức HTTP/1 cung cấp 2 cách để xác định điểm kết thúc của 1 request đó là dựa vào 2 header: **Content-Length** và header **Transfer-Encoding**.

- Header **Content-Length** chỉ độ dài của phần message tính theo byte:

```http
POST /search HTTP/1.1
Host: normal-website.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 11

q=smuggling
```

- Header **Transfer-Encoding** chỉ ra kiểu truyền tải nào được áp dụng tới phần message body. Mình sẽ nói đến kiểu **chunked encoding** (mã hóa phân mảnh?).
Khi dữ liệu được chunked, nó sẽ có dạng như sau:
  - Kí tự `b` đầu tiên là **kích thước của đoạn chunked** theo dạng hex.
  - Tiếp theo là **nội dung chunked**.
  - Kết thúc là **số 0**.

```http
POST /search HTTP/1.1
Host: normal-website.com
Content-Type: application/x-www-form-urlencoded
Transfer-Encoding: chunked

b
q=smuggling
0
```

- Vì HTTP/1 cung cấp cả 2 phương pháp khác nhau để xác định chiều dài của message nên một message có thể sử dụng được cả 2 cách cùng lúc, dẫn đến conflict. Mặc dù giao thức HTTP/1 đã ngăn chặn vấn đề này bằng cách quy định: nếu cả 2 header **Content-Length** và **Transfer-Encoding** đều có mặt thì header **Content-Length** phải bị bỏ qua.
- Tuy nhiên quy định này có thể đúng khi chỉ có một server tham gia xử lý, khi xuất hiện hai hoặc nhiều server được nối chuỗi với nhau có thể xuất hiện lỗ hổng trong tình huống:
  - Một số server ko hỗ trợ header `Transfer-Encoding`.
  - Một số server có hỗ trợ header `Transfer-Encoding` nhưng có thể bị obfuscated để bỏ qua nó theo 1 cách nào đó.

Nếu front-end và back-end có các cách xử lí khác nhau với header `Transfer-Encoding`, chúng sẽ ko thống nhất được đâu là boundary giữa các request liên tiếp từ đó dẫn đến lỗ hổng nguy hiểm này.

---

## IV. Cách thực hiện một cuộc tấn công HTTP Request Smuggling

Các cuộc tấn công **HTTP Request Smuggling** cơ bản đều xoay quanh việc đặt cả 2 header `Content-Length` và `Transfer-Encoding` vào trong cùng 1 request sử dụng giao thức HTTP/1, đồng thời phải thao túng sao cho server **front-end** và **back-end** xử lý request đó theo 2 cách khác nhau. Sau đây là các cách để thực hiện điều này:
- **CL.TE**: **front-end** sử dụng `Content-Length` và **back-end** sử dụng `Transfer-Encoding`
- **TE.CL**: **front-end** sử dụng `Transfer-Encoding` và **back-end** sử dụng `Content-Length`
- **TE.TE**: **front-end** sử dụng `Transfer-Encoding` và **back-end** sử dụng `Transfer-Encoding`

### 1. Lỗ hổng CL.TE

Trong kịch bản này, front-end sử dụng header **Content-Length** và back-end sử dụng header **Transfer-Encoding**.
Sau đây là cách thực hiện một cuộc tấn công HTTP Request Smuggling:

```http
POST / HTTP/1.1
Host: vulnerable-website.com
Content-Length: 13
Transfer-Encoding: chunked

0

SMUGGLED
```

- **Front-end** xử lí header **Content-Length** và xác định rằng message body có độ dài 13 byte, kết thúc ngay sau chữ **SMUGGLED**. Toàn bộ request này được chuyển tiếp đến **back-end**.
- **Back-end** xử lý header **Transfer-Encoding**, do đó nó coi message body đang sử dụng kiểu **chunked**. Trước hết nó xử lý chunk đầu tiên, được khai báo là có độ dài bằng **0**, do đó nó coi như request đã kết thúc tại đây. Điều này dẫn đến các byte tiếp theo, từ **SMUGGLED** bị bỏ lại ko được xử lý và chính những byte này là phần mở đầu của request tiếp theo trong chuỗi.

#### Thực hành Lab: HTTP request smuggling, basic CL.TE vulnerability

* **Link Lab:** [https://portswigger.net/web-security/request-smuggling/lab-basic-cl-te](https://portswigger.net/web-security/request-smuggling/lab-basic-cl-te)

![image](https://hackmd.io/_uploads/BkM_DJStzl.png)

Mục tiêu của lab là smuggle 1 cái request đến back-end server để request tiếp theo khi được xử lí bởi back-end sẽ sử dụng method `GPOST`, biết front-end server chỉ chấp nhận các request có method là `GET` hoặc `POST`.

- Bước đầu tiên cần bắt 1 request đến lab và loại bỏ đi các header ko cần thiết và bổ sung 2 header **Content-Length** và **Transfer-Encoding** để phát hiện lỗ hổng này thuộc kiểu nào.
Mày mò 1 lúc thì mình tìm được một số cách dò mà các tool tự động Scanner sử dụng:

![image](https://hackmd.io/_uploads/B1VwnlHKGg.png)

- Dựa trên sơ đồ trên, tạo 1 payload để kiểm tra xem web đang bị dính lỗ hổng nào:

![image](https://hackmd.io/_uploads/rJML5grYfl.png)

Nhận thấy sau một hồi thì back-end server mới trả response time out:

![image](https://hackmd.io/_uploads/rkav9eHKzg.png)

Đối chiếu với sơ đồ cây trên thì khả năng lỗ hổng này thuộc kiểu **CL.TE**.
Phân tích cụ thể hơn 1 chút:
- Request trên có **Content-Length** là **6** nên nếu front-end server chỉ xử lí header này thì sẽ chỉ nhận đến hết chuỗi **xyz** và bỏ qua **X**, cuối cùng chuyển tiếp cho back-end server.
- Giả sử anh bạn back-end xử lí header **Transfer-Encoding**, khi đó request được front-end chuyển tiếp tới là:

![image](https://hackmd.io/_uploads/B1tRWwHtzg.png)

Nhận thấy chunk đầu tiên có độ dài 3 byte có data là **xyz**. Tuy nhiên, theo chuẩn chunked sau chunk đầu tiên phải có thêm một cặp `\r\n` và sau đó là các khối khác (hoặc khối 0 để kết thúc). Vì front-end không gửi phần đó qua, back-end sẽ cứ đứng chờ mãi cho đến khi bị **timeout** như ở kết quả response.

![image](https://hackmd.io/_uploads/B1yOXvHYfe.png)

- Dự đoán được lỗ hổng thuộc kiểu **CL.TE** thì tạo ra payload dựa vào phần **IV.1** thôi là done. Sau đây là hình vẽ minh họa cách tấn công:

![image](https://hackmd.io/_uploads/SJrHrwSFGx.png)

Và lab đã được giải quyết 🤓:

![image](https://hackmd.io/_uploads/HJugalHFzl.png)

---

### 2. Lỗ hổng TE.CL

Ở kịch bản này, front-end sử dụng header `Transfer-Encoding` và back-end sử dụng `Content-Length`. Khi đó có thể thực hiện tấn công HTTP Request Smuggling bằng 1 message body đơn giản sau:

```http
POST / HTTP/1.1
Host: vulnerable-website.com
Content-Length: 3
Transfer-Encoding: chunked

8
SMUGGLED
0
```

- Do front-end xử lý header **Transfer-Encoding** nên phần message body sử dụng mã hóa phân mảnh (**chunked**). Chunked đầu tiên có độ dài là 8 byte, chứa chuỗi **SMUGGLED**, tiếp theo là chunk có độ dài **0**, dẫn đến kết thúc request. Toàn bộ request này được chuyển tiếp đến back-end.

> **Lưu ý:** Khi gửi request để kết thúc chuỗi cần thêm các chuỗi ký tự ngắt dòng `\r\n` 2 lần ngay sau số 0:
> ```text
> 0\r\n
> \r\n
> ```
{: .prompt-warning }

- Máy chủ back-end thì lại xử lý request theo header **Content-Length** nên chỉ nhận **3 byte** như đã khai báo trong message body bao gồm **`8\r\n`**. Nhận thấy các byte tiếp theo bắt đầu từ **byte S** bị bỏ lại, ko xử lí nên sẽ được ghép với phần đầu của request tiếp theo trong chuỗi.

#### Thực hành Lab: HTTP request smuggling, basic TE.CL vulnerability

* **Link Lab:** [https://portswigger.net/web-security/request-smuggling/lab-basic-te-cl](https://portswigger.net/web-security/request-smuggling/lab-basic-te-cl)

![image](https://hackmd.io/_uploads/Hk7kxPBFGl.png)

Yêu cầu tương tự như lab trên nên vào đấm luôn xem lỗ hổng này thuộc kiểu nào dựa trên sơ đồ cây:

![image](https://hackmd.io/_uploads/SypwUvBYMg.png)

Gửi request đầu tiên và nhận về kết quả `400 Bad Request`:

![image](https://hackmd.io/_uploads/SkiFwDrYGl.png)

Điều này chứng tỏ khả năng front-end đã reject với lí do `{"error":"Invalid request"}`, do đó khả năng cao phía front-end đã xử lí header **Transfer-Encoding** vì phần data trong message body trên chưa tuân theo chuẩn chunked encoding.
Vậy đã thu hẹp được giới hạn của lỗ hổng là **TE.CL** hoặc **TE.TE**. Gửi tiếp request để xác định:

![image](https://hackmd.io/_uploads/ry7-9PSYGx.png)

Với request trên thì server trả về response timeout, vì thế có thể kết luận đây là lỗ hổng **TE.CL** do phía back-end chỉ nhận được request:

![image](https://hackmd.io/_uploads/SkCU9vSKMl.png)

Trong khi back-end lại xử lí header **Content-Length** và khai báo là 6 byte ở gói tin, mà chunk hiện tại đã có 5 byte rồi nên máy chủ cứ chờ byte cuối cùng đến như cách bạn chờ crush rep tin nhắn dẫn đến timeout response :<

![image](https://hackmd.io/_uploads/HJBA5DBKfl.png)

Ko chờ nữa, cần tìm cách để tấn công kiểu lỗ hổng này với mục tiêu là gửi 1 request có method `GPOST`. Mình nghĩ đến việc chèn 1 request method `GPOST` vào chunk.
Request này có 92 bytes nên `5c` là mã hexa của độ dài request.

![image](https://hackmd.io/_uploads/ry_bVuBtGe.png)

Sau đó là dấu hiệu kết thúc chuỗi với chunk có độ dài 0. Khi đó back-end chỉ nhận được 4 byte đầu là **`5c\r\n`**, phần còn lại sẽ ghép sang request ngay sau đó.

**Tại sao Content-Length lại bằng 11?** (thực ra lớn hơn hoặc bằng 10 là được) nhưng nếu là 11 thì sẽ trả về kết quả rõ hơn.
Do hiện tại, phần body của request được smuggled đã có 10 byte rồi. Nên chỉ cần gửi nguyên phần request được smuggle trên tới back-end xử lý là đã hoàn thành lab, tuy nhiên thì nó sẽ ko trả về lỗi kiểu `"Unrecognized method GPOST"` đâu. Lí do là vì nó chỉ trả về response cho gói tin POST ban đầu thôi còn response của request có method GPOST sẽ tan biến và ko thể nhìn thấy. Tóm lại khi để **Content-Length** là 10 thì chỉ với 1 HTTP Request trên, back-end server đã xử lí thành 2 request khác nhau.

![image](https://hackmd.io/_uploads/ryYTyuHKMx.png)

Vậy nên cần bắt cóc 1 byte của request sau đó để ghép vào request smuggle thì request tiếp theo sẽ fail, nếu là `POST` thì sẽ thành `OST` do bị mất 1 byte và ko tồn tại method này.
Gửi lại request đó một lần nữa thì lab hoàn thành với kết quả như mong muốn:

![image](https://hackmd.io/_uploads/rJXspwHYfl.png)

---

### 3. Lỗ hổng TE.TE

Ở kịch bản này, cả front-end và back-end đều hỗ trợ header `Transfer-Encoding`, nhưng mình có thể trôn 1 trong 2 máy chủ để nó ko xử lý header này bằng cách làm rối nó lên (**obfuscate**).
Có rất nhiều cách obfuscate khác nhau. VD như:

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

Nói chung, mỗi cách trên đều có một sự sai lệch nhỏ so với chuẩn đặc tả của giao thức **HTTP**. Trong thực tế người ta cũng hiếm khi tuân thủ các đặc tả của giao thức một cách tuyệt đối chính xác, nên các hệ thống khác nhau sẽ có mức độ **tolerate** khác nhau đối với các biến thể khác so với chuẩn.

Zậy nên, để phát hiện ra lỗ hổng **TE.TE** cần tìm ra một biến thể của header **Transfer-Encoding** sao cho chỉ 1 trong 2 máy chủ front-end hoặc back-end xử lý nó thôi. Một khi đã đào lửa được, thì phần còn lại đã được biên hết rồi (theo 1 trong 2 kịch bản trên mà tấn công thôi).

#### Thực hành Lab: HTTP request smuggling, obfuscating the TE header

* **Link Lab:** [https://portswigger.net/web-security/request-smuggling/lab-obfuscating-te-header](https://portswigger.net/web-security/request-smuggling/lab-obfuscating-te-header)

![image](https://hackmd.io/_uploads/rkbdf6ItMe.png)

Đề bài vẫn giống 2 lab trên thôi nên ko table nữa:

![image](https://hackmd.io/_uploads/SypwUvBYMg.png)

Một lần nữa lại sử dụng sơ đồ cây để dò lỗ hổng:

![image](https://hackmd.io/_uploads/r1tIB3LYGe.png)

Có thể thấy với request trên máy chủ front-end đã từ chối với thông báo `"invalid request"`, chứng tỏ máy chủ này đã xử lí header **Transfer-Encoding**.
Túc tiệp với payload sau để xác định back-end có hỗ trợ header **Transfer-Encoding** ko:

![image](https://hackmd.io/_uploads/HyaqBhLYMl.png)

Và kết quả là timeout, chứng tỏ back-end có hỗ trợ header **Transfer-Encoding**. Vậy đã xác định được lỗ hổng thuộc kiểu **TE.TE**.
Quay trở lại lí thuyết, tìm cách để làm rối cái header này sao cho chỉ 1 trong 2 máy chủ xử lý header này thôi. Sau khi thử 1749 lần, mình đã thành công bằng cách nhét thêm header `Transfer-Encoding` với 1 giá trị bất kì:

![image](https://hackmd.io/_uploads/rkgMRhLFMl.png)

Payload này đã làm back-end **timeout**, chứng tỏ front-end vẫn xử lí header **Transfer-Encoding**, back-end đã bị lừa thành công và chỉ xử lí header **Content-Length**. Khả năng do back-end cấu hình nhận giá trị của header sau cùng nên khi đó **Transfer-Encoding** có giá trị là `x`, dẫn tới nó ko xử lí được kiểu chunked.

![image](https://hackmd.io/_uploads/r1NUWTLtfl.png)

Đến đây thì sử dụng payload ở kịch bản của lỗ hổng **TE.CL** là xong:

![image](https://hackmd.io/_uploads/BJHWkp8Fzg.png)

---

### Luyện tập thêm

Để làm quen với lỗ hổng này có thể làm thêm 2 bài lab trên PortSwigger:
- [Confirming CL.TE via differential responses](https://portswigger.net/web-security/request-smuggling/finding/lab-confirming-cl-te-via-differential-responses)
- [Confirming TE.CL via differential responses](https://portswigger.net/web-security/request-smuggling/finding/lab-confirming-te-cl-via-differential-responses)