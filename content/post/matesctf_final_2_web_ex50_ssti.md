---
title: "Matesctf final 2 - SSTI"
date: 2018-09-08T09:46:55+07:00
draft: false
author: "Kev"
comments: true
tags: ["ctf", "flask"]
---
{{< figure src="/images/uploads/ex50.PNG" width="100%">}}

## EXPLOIT  - [source](/resources/matesctf/ex50.tar)
<hr>
Matesctf final được tổ chức theo dạng attack/defense. Cụ thể tác giả sẽ build web service trên server của mình, tức là cho source. Từng đội sẽ nghiên cứu lổ hổng trên server mình và exploit server đội khác để lấy flag.

Có một lỗi trong bài web 1 là tài khoản của bot-check của BTC được gán mặc định và đội nào cũng như nhau `admin:1`. Vừa bắt đầu cuộc thi 15 phút thì tác giả đã nhắc nhở mọi người không nên đổi password của bot tránh trường hợp bot không thể check và bị mất điểm service. Với tài khoản admin này, có chức năng đổi mật khẩu nhưng không token CSRF và những cơ chế ràng buộc khác. Chính vì vậy, đội mình viết script sửa flag của admin tất cả các đội còn lại. Tất cả các đội đều mất điểm service, mặc dù phút cuối bị UIT-r3s0L và BKHN.ACEBEAR giành lại admin trong ít phút.

{{< figure src="/images/uploads/ex50-2.png" title="Các đội đều mất điểm service ở challenge cuối" >}}

Ban đầu mình fuzzing một lúc thì tìm được chức năng download file. Mình liền nghĩ đến LFI và ý nghĩ này tồn tại không quá 5 phút, biết là bị tác giả dụ rồi. Thôi bỏ qua. {{<emoji ah>}}

Đến khi có hint 1 mình mới exploit được bài này `404 not found`. Tìm bug tại chỗ xử lý request 404

{{<highlight python3>}}
@app.errorhandler(404)
    def page_not_found(error):
        app.logger.info(error)
        if type(error.description) == dict:
            return jsonify(error=error.description), 405
        else:
            return render_template_string('Page %s not Found'%request.base_url), 404
{{</highlight>}}

Sử dụng payload `{{4*4}}[[5*5]]` để fuzz thì ra bug liền. {{<emoji lol>}}
	
{{< figure src="/images/uploads/ex50-3.png"  width="100%">}}

Thông thường SSTI sử dụng dấu {} để khai thác nhưng trường hợp này thì dùng [] . Mọi chuyện xảy ra là do đây, Tác giả đã thay đổi đi chút ít cho khác xíu thôi.
{{<highlight python3>}}
class CustomFlask(Flask):
    jinja_options = Flask.jinja_options.copy()
    jinja_options.update(dict(
        variable_start_string='[[',
        variable_end_string=']]'
    ))
{{</highlight>}}


 - `__mro__` — Method Resolution Order: là danh sách các class mà đối tượng đó kế thừa.

{{< figure src="/images/uploads/ex50-4.png"  width="100%">}}
 
 - Sẽ chọn đối tượng lớn nhất là object sau đó gọi `__subclasses__()` tức là chứa các lớp con của object . Trong đây chứa tất cả các đối tượng có trong context (môi trường hiện tại). Có rất nhiều các đối tượng bên trong. Vừa dùng `__mro__` và `__subclasses__()` để lấy được 1 đối tượng nào đó trong context có thể lợi dụng được.

{{< figure src="/images/uploads/ex50-5.png" >}}

Nhiệm vụ bây giờ của mình là lợi dụng được class nào để đọc file flag trên server hay không? Trong đây mình tìm được 2 thứ có vẻ thú vị là `<class 'subprocess.Popen'>` ở vị trí 208 và `<type 'file'>` ở vị trí 40. Mình có vẻ hơi gà nên không biết cách execute shell bằng Popen, vì thế cuối cùng là dùng file cho nhanh gọn lẹ. {{<emoji rap>}} Payload cuối cùng thế này:

{{< figure src="/images/uploads/ex50-6.png"  width="100%">}}

## SOLUTION
<hr>
To be continue ...
