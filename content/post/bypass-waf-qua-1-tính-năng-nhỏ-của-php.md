---
title: Bypass WAF qua 1 tính năng nhỏ của PHP
date: '2019-05-04T22:31:21+07:00'
categories:
  - 1day
tags:
  - waf
Archives: '2019'
autoThumbnailImage: false
thumbnailImagePosition: top
coverImage: ''
---
## 1. Tính năng hay lỗi?  
PHP là ngôn ngữ lập trình web đơn giản, gọn nhẹ và dễ lập trình nhưng tiềm ẩn nhiều lỗi. Bằng chứng là có nhiều phiên bản được cập nhật hàng tháng chỉ nhầm vá những lỗi ở phiên bản cũ.  
Phiên bản PHP hiện tại là 7.3 nhưng đã có bản thử nghiệm của 7.4 rồi.  
Trong giới hạn bài này, tôi sẽ giới thiệu cho bạn 1 tính năng nhưng được tận dụng để trở thành lỗi có thể qua mặt được một số WAF đình đám hiện nay, ví dụ như mod security.  
Mô tả của tác giả:  
##### Dots in incoming variable names  
_Typically, PHP does not alter the names of variables when they are passed into a script. However, it should be noted that the dot (period, full stop) is not a valid character in a PHP variable name. For the reason, look at it:_
```
<?php
$varname.ext;  /* invalid variable name */
?>
```
_Now, what the parser sees is a variable named $varname, followed by the string concatenation operator, followed by the barestring (i.e. unquoted string which doesn't match any known key or reserved words) 'ext'. Obviously, this doesn't have the intended result.
For this reason, it is important to note that PHP will automatically replace any dots in incoming variable names with underscores._  

Điều này chính là, khi user truyền vào 1 tên biến, tên cookie hay ngay cả tên trường header có chứa dấu dot `.` thì PHP sẽ tự hiểu là underscore `_`. Ngay chỗ này, đã gây ra một số rủi ro và nhầm lẫn không đáng có.  
Ngoài dấu chấm thì còn dấu nào khác nữa không? Mình viết 1 script đơn giản để kiểm tra thì có tất cả 3 kí tự bị ảnh hưởng. 
- chr(32) ( ) (space)
- chr(46) (.) (dot)
- chr(91) ([) (open square bracket)  

Đào xuống source C xem thế nào nhé:  
[php_variables.c](https://github.com/php/php-src/blob/master/main/php_variables.c):
{{<highlight php "linenos=inline,hl_lines=107-108,linenostart=98">}}  
    /*
	 * Prepare variable name
	 */
	var_len = strlen(var_name);
	var = var_orig = do_alloca(var_len + 1, use_heap);
	memcpy(var_orig, var_name, var_len + 1);

	/* ensure that we don't have spaces or dots in the variable name (not binary safe) */
	for (p = var; *p; p++) {
		if (*p == ' ' || *p == '.') {
			*p='_';
		} else if (*p == '[') {
			is_array = 1;
			ip = p;
			*p = 0;
			break;
		}
	}
	var_len = p - var;
{{</highlight>}}  

{{<highlight php "linenos=inline,hl_lines=193,linenostart=191">}}  
if (!ip) {
	/* PHP variables cannot contain '[' in their names, so we replace the character with a '_' */
	*(index_s - 1) = '_';
	index_len = 0;
	if (index) {
		index_len = strlen(index);
	}
	goto plain_var;
	return;
}  
{{</highlight>}}  

Tại dòng 107, 108 và 193 tác giả đã cố ý replace 3 dấu `<space>`, `.` và `[` trở thành `_` ở trong tên biến để tránh một số trường hợp phát sinh gây ra lỗi tại các module tính năng khác.  

## 2. Mod security và crs owasp rule  
### [Mod security](https://github.com/SpiderLabs/ModSecurity)
_Libmodsecurity is one component of the ModSecurity v3 project. The library codebase serves as an interface to ModSecurity Connectors taking in web traffic and applying traditional ModSecurity processing. In general, it provides the capability to load/interpret rules written in the ModSecurity SecRules format and apply them to HTTP content provided by your application via Connectors._  
Modsecurity là một ứng dựng tường lửa tầng mạng, hoạt động ở layer 7 trong mô hình 7 tầng OSI. Tính năng được biết đến nhiều nhất là: thay đổi, chặn bắt, chuyển tiếp các tham số trong HTTP request của người dùng sau đó chuyển cho web server xử lý. Sau khi web server xử lý xong, HTTP response cũng phải được modsecurity xem qua sau đó mới trả về cho người dùng.  
![Modsecurity working](https://www.indusface.com/blog/wp-content/uploads/2017/11/WAF.png)  
Cơ chế là modsecurity dựa trên các rule được định nghĩa sẵn, khá phức tạp nên không dành cho người mới, đây có thể xem là yếu điểm đầu tiên của WAF này. Tuy nghiên, modsecurity khá nhỏ gọn, nhanh và hiệu quả cao. Dưới đây là 1 ví dụ đơn giản của rule:  
```
SecRule ARGS_NAMES "@rx [^a-z0-9]+"\
	"id:2019,\
	phase:2,\
	t:none,t:lowercase,t:urlDecode,t:urlDecodeUni\
	deny,log,\
	status:403,\
	tag:blog.kevinlpd.tk\
	msg:'Hacking Detected - bypass waf'"
```

### [Crs owasp rule](https://github.com/SpiderLabs/owasp-modsecurity-crs)  
_The OWASP ModSecurity Core Rule Set (CRS) is a set of generic attack detection rules for use with ModSecurity or compatible web application firewalls. The CRS aims to protect web applications from a wide range of attacks, including the OWASP Top Ten, with a minimum of false alerts._  
Để tăng tính hiệu quả cho modsecurity, tổ chức OWASP đã bổ sung thêm bộ rule hoạt động chặn các lỗi phổ biến như: sql injection, xss, upload, ... Thậm chí, còn viết rule riêng cho các framework, CMS nổi tiếng như: drupal, wordpress, ...  
Bộ rule này khá phức tạp để hiểu và debug được. Thông thường người dùng chỉ việc tải về và include vào để chạy thôi không quan tâm nhiều. Còn người dùng nào muốn WAF hoạt động theo từng trường hợp cụ thể thì có thể tìm hiểu và tự viết rule.

### 3. Bypass rule crs
Khi chúng tôi phát hiện ra vấn đề này, chính trick này đã bypass đa số các rule của WAF trong hệ thống công ty chúng tôi. Tôi đã nãy sinh ra ý tưởng tìm lỗi trong rule crs xem có chút may mắn nào không. Đúng thật là tôi tìm ra khá nhiều nhưng tận dụng được thì hiện tôi chỉ tìm ra được 2 rule nhưng impact không cao. Tôi sẽ tiếp tục tìm hiểu thêm.  
Tôi đã report cho modsecurity trên github, được confirmation và đã fix. Bạn vào đây để xem chi tiết [#1386](https://github.com/SpiderLabs/owasp-modsecurity-crs/issues/1386)  
__Rule id=933110__ trong file [REQUEST-933-APPLICATION-ATTACK-PHP.conf](https://github.com/SpiderLabs/owasp-modsecurity-crs/blob/e5cbc1af12979cfbb7c8b36e5359d48c4f56c551/rules/REQUEST-933-APPLICATION-ATTACK-PHP.conf)
```
#
# [ PHP Script Uploads ]
#
# Block file uploads with filenames ending in PHP related extensions
# (.php, .phps, .phtml, .php5 etc).
#
# Many application contain Unrestricted File Upload vulnerabilities.
# https://www.owasp.org/index.php/Unrestricted_File_Upload
#
# Attackers may use such a vulnerability to achieve remote code execution
# by uploading a .php file. If the upload storage location is predictable
# and not adequately protected, the attacker may then request the uploaded
# .php file and have the code within it executed on the server.
#
# Also block files with just dot (.) characters after the extension:
# https://community.rapid7.com/community/metasploit/blog/2013/08/15/time-to-patch-joomla
#
# Some AJAX uploaders use the nonstandard request headers X-Filename,
# X_Filename, or X-File-Name to transmit the file name to the server;
# scan these request headers as well as multipart/form-data file names.
#
SecRule FILES|REQUEST_HEADERS:X-Filename|REQUEST_HEADERS:X_Filename|REQUEST_HEADERS:X-File-Name "@rx .*\.(?:php\d*|phtml)\.*$" \
    "id:933110,\
    phase:2,\
    block,\
    capture,\
    t:none,t:lowercase,\
    msg:'PHP Injection Attack: PHP Script File Upload Found',\
    logdata:'Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}',\
    tag:'application-multi',\
    tag:'language-php',\
    tag:'platform-multi',\
    tag:'attack-injection-php',\
    tag:'OWASP_CRS/WEB_ATTACK/PHP_INJECTION',\
    tag:'OWASP_TOP_10/A1',\
    ctl:auditLogParts=+E,\
    ver:'OWASP_CRS/3.1.0',\
    severity:'CRITICAL',\
    setvar:'tx.msg=%{rule.msg}',\
    setvar:'tx.php_injection_score=+%{tx.critical_anomaly_score}',\
    setvar:'tx.anomaly_score_pl1=+%{tx.critical_anomaly_score}',\
    setvar:'tx.%{rule.id}-OWASP_CRS/WEB_ATTACK/PHP_INJECTION-%{MATCHED_VAR_NAME}=%{tx.0}'"
```
và __rule id=933111__ cũng trong cùng file đó  
```
#
# [ PHP Script Uploads: Superfluous extension ]
#
# Block file uploads with PHP related extensions (.php, .phps, .phtml,
# .php5 etc) anywhere in the name, followed by a dot.
#
# Example: index.php.tmp
#
# Uploading of such files can lead to remote code execution if
# Apache is configured with AddType and MultiViews, as Apache will
# automatically do a filename match when the extension is unknown.
# This configuration is fortunately not common in modern installs.
#
# Blocking these file names might lead to more false positives.
#
# Some AJAX uploaders use the nonstandard request headers X-Filename,
# X_Filename, or X-File-Name to transmit the file name to the server;
# scan these request headers as well as multipart/form-data file names.
#
# This rule is a stricter sibling of rule 933110.
#
SecRule FILES|REQUEST_HEADERS:X-Filename|REQUEST_HEADERS:X_Filename|REQUEST_HEADERS:X-File-Name "@rx .*\.(?:php\d*|phtml)\..*$" \
    "id:933111,\
    phase:2,\
    block,\
    capture,\
    t:none,t:lowercase,\
    msg:'PHP Injection Attack: PHP Script File Upload Found',\
    logdata:'Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}',\
    tag:'application-multi',\
    tag:'language-php',\
    tag:'platform-multi',\
    tag:'attack-injection-php',\
    tag:'OWASP_CRS/WEB_ATTACK/PHP_INJECTION',\
    tag:'OWASP_TOP_10/A1',\
    tag:'paranoia-level/3',\
    ctl:auditLogParts=+E,\
    ver:'OWASP_CRS/3.1.0',\
    severity:'CRITICAL',\
    setvar:'tx.msg=%{rule.msg}',\
    setvar:'tx.php_injection_score=+%{tx.critical_anomaly_score}',\
    setvar:'tx.anomaly_score_pl3=+%{tx.critical_anomaly_score}',\
    setvar:'tx.%{rule.id}-OWASP_CRS/WEB_ATTACK/PHP_INJECTION-%{MATCHED_VAR_NAME}=%{tx.0}'"
```  
Rule đặt điều kiện kiểm tra `REQUEST_HEADERS:X_Filename` có tồn tại và chứa tên file dạng: shell.php hay shell.php.tmp thì chặn. Dùng header `X_Filename` này để upload file shell.php lên server nhưng cách này không phổ biến lắm, cho nên mình nói ngay lúc đầu là impact không cao. Cụ thể bypass xem HTTP request bên dưới:  
```http
GET /test.php HTTP/1.1
Host: localhost
Accept: */*
X.Filename: test.php.tmp
Connection: close
```  
Ghi chú: có vài bạn sẽ hỏi tại sao tôi không report dấu `<space>` và `[`? Vì dấu này không hoạt động được trên HTTP Header, lý do thì tôi phải mò source C để đọc thôi. 

## 4. Áp dụng vào CTF
... Tôi sẽ viết sau kì CTF kết thúc, dự kiến cuối tháng 5 ...
