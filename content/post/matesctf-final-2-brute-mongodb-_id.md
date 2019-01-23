---
title: Matesctf final 2 - Brute mongodb _id
date: '2018-09-13T23:01:18+07:00'
categories:
  - CTF
tags:
  - CTF
  - matesctf
Archives: '2018'
autoThumbnailImage: false
thumbnailImagePosition: top
thumbnailImage: ''
coverImage: /images/uploads/ex50-11.png
---
## EXPLOIT - [source](/resources/ex50.tar)

<hr>

Trong source web có 1 file log ghi lại hành động của bot khi insert dữ liệu vào database. Từ thông tin đấy, có thể dễ dàng đoán là trong database có flag.

```
2018-08-21 10:48:38.035547 added page 1
2018-08-21 10:48:38.039078 added page 2
2018-08-21 10:48:38.039908 added page 3
2018-08-21 10:48:38.040720 added page 4
2018-08-21 10:48:38.041323 added page 5
2018-08-21 10:48:38.042003 added page 6
2018-08-21 10:48:38.042624 added page 7
2018-08-21 10:48:38.043379 added page 8
2018-08-21 10:48:38.044061 added page 9
2018-08-21 10:50:03.126937 added flag to db
```

Xem xét trong database, đúng là có flag thật.

```
> db.novel.find({},{"_id":1, "page":1})
{ "_id" : ObjectId("5b7c26465f627d2737a17c3a"), "page" : 9 }
{ "_id" : ObjectId("5b7c269b5f627d2737a17c3b") }
{ "_id" : ObjectId("5b7c26465f627d2737a17c32"), "page" : 1 }
{ "_id" : ObjectId("5b7c26465f627d2737a17c33"), "page" : 2 }
{ "_id" : ObjectId("5b7c26465f627d2737a17c34"), "page" : 3 }
{ "_id" : ObjectId("5b7c26465f627d2737a17c35"), "page" : 4 }
{ "_id" : ObjectId("5b7c26465f627d2737a17c36"), "page" : 5 }
{ "_id" : ObjectId("5b7c26465f627d2737a17c37"), "page" : 6 }
{ "_id" : ObjectId("5b7c26465f627d2737a17c38"), "page" : 7 }
{ "_id" : ObjectId("5b7c26465f627d2737a17c39"), "page" : 8 }
> db.novel.find({"_id": ObjectId("5b7c269b5f627d2737a17c3b")})
{ "_id" : ObjectId("5b7c269b5f627d2737a17c3b"), "content" : "matesctf{23w4324234234234234}\n" }
```

Hướng tiếp theo là tìm trên giao diện web, có thể exploit ở đâu để có thể gọi flag ra. Liên quan đến cơ sở dữ liệu thường sẽ nghĩ đến nosql injection. Nhưng trường hợp này thì không.

Sau khi đăng nhập bằng tài khoản bot `admin:1` được cung cấp từ trước. Tác giả cho ta đọc truyện `Yêu Nhầm Chị Hai Được Nhầm Em Gái`, ohh man, really nigga? {{<emoji beauty>}} Có công mài sức có ngày nên kim, ai bỏ thời gian đọc hết truyện thì sẽ được thưởng, nhưng tôi thì không, tôi lười lắm nên tôi tìm cách khác. Khi `next` sang trang tiếp, đến trang thứ 9 thì không thể next thế nào cho ra trang 10 được. Nhìn lại file log thì có thể đoán được lỗi ở đây.

Tiếp tục review sourcecode để tìm hướng exploit. Trong file `users.py` xử lý page id, nhận giá trị id và select ra nội dung truyện từ cơ sở dữ liệu. Nếu xảy ra lỗi thì thay vì nhận giá trị page id thì lại nhận object id. ahhh, `con bọ` nằm ở đây này {{<emoji boom>}}.

{{<highlight python>}}
@routes.route('/page/<page>',methods=\['GET'])
def page(page):
    try:
        data = Novel.find_one({"page":int(page)})
        lines = data\['content'].split("\n")
    except Exception, e:
        from bson.objectid import ObjectId
        try:
            data = Novel.find_one({"_id":ObjectId(page)})
            lines = data\['content'].split("\n")
        except:
            lines = \[]
        return render_template('index.html',page=int(page,16),message=lines,_id=page)
    if session.has_key('usn'):
        return render_template('index.html',_id=data\['_id'], message=lines, page=int(page))
    return render_template('login.html',ip=request.remote_addr)
{{</highlight>}}

Chỉ cần gửi lên giá trị object id của flag trong cơ sở dữ liệu thì sẽ nhận được flag.

{{<figure src="/images/uploads/ex50-12.png">}}

Nhưng làm sao để có được object id trên cơ sở dữ liệu của người khác, tôi có được là do tôi test trên local của đội mình. Vậy phải làm sao? Tôi không hiểu biết quá nhiều về mongo nên tôi search google về cách generate ra object id.

May quá, trên [trang chủ](https://docs.mongodb.com/manual/reference/method/ObjectId/) của mongo có nói rất rõ về số object id. Độ dài của object id là 12 byte. 

* 4 byte đầu là giá trị timestamp
* 5 byte kế là giá trị random 
* 3 byte cuối là giá trị số đếm


```
ObjectId(<hexadecimal>)
Returns a new ObjectId value. The 12-byte ObjectId value consists of:

a 4-byte value representing the seconds since the Unix epoch,
a 5-byte random value, and
a 3-byte counter, starting with a random value.
```

Tôi đã lấy vài giá trị object id trong local mình ra để phân tích. Theo như 3 dãy số bên dưới, ta thấy:

* Timestamp cách nhau không quá xa, nhiều nhất là khác nhau 1 byte cuối
* 5 byte giá trị random là giống nhau, có vẻ là chỉ random 1 lần và không random lại
* 3 byte cuối là số đếm nên gần như chỉ khác nhau 4 bit cuối, tôi không chắc, cũng có thể khác nhau tận 1 byte.

Cho nên dễ rút ra kết luận, nếu ta biết 1 giá trị object id nào đó trong database, thì chỉ cần bruteforce 2 byte. Nhưng tôi đã test thử trên local, để brute được 2 byte thì máy tôi cần 100 thread request http và mất 6 phút để làm việc đó -> quá lâu {{<emoji canny>}}

```
5b7c2646 5f627d2737 a17c3a
5b7c269b 5f627d2737 a17c3b
5b7c2646 5f627d2737 a17c32
```

Có cách nào đó khác. Bạn hãy xem lại file log ở trên, có thông tin của timestamp, chúng ta có thể lợi dụng đều đó. Tức là mỗi lần bot insert flag vào cơ sở dữ liệu của 1 đội nào đó thì cũng insert dữ liệu và cơ sở dữ liệu của đội khác cách nhau tầm vài giây, ở đây mình dự đoán tối đa là 5 giây. Cho nên, timestamp xem như là mình đã biết được.

Payload ở [đây này](/resources/brute_id.py).
