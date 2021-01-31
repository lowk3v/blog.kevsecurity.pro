---
title: SSRF in Liferay Portal
date: '2019-07-15T09:46:15+07:00'
categories:
  - 1day
Archives: '2019'
autoThumbnailImage: false
thumbnailImagePosition: top
coverImage: /images/uploads/annotation-2019-07-15-094719.png
---
# Theo dõi Known vulnerabilities
Để theo dõi mỗi khi lập trình viên cập nhật bản vá cho nhiều lỗi bảo mật gì đó, từ những thông tin ít ỏi đó mà mình lần mò và khai thác lỗi. Ví dụ như thế này
```
Liferay Portal 7.1 CE GA3 and older unsupported versions and older unsupported versions is vulnerable to Server-Side Request Forgery (SSRF) via DDM REST Data Provider which allows an attacker access to sensitive information.
```
và thế này
```
There is no patch available for Liferay Portal 7.1 CE GA3. Instead, users should upgrade to Liferay Portal 7.1 CE GA4 (7.1.3) or later to fix this issue.
```
Mình có được vài thông tin quan trọng như sau: lỗi SSRF, module lỗi DDM REST Data Provider, phiên bản lỗi trước 7.1.3 và vá lỗi ở phiên bản 7.1.3.

# Diff để tìm ra vị trí vá lỗi
Bằng cách dùng công cụ diff mã nguồn 2 phiên bản 7.1.2 và 7.1.3 của liferay và phạm vi là module DDM REST Data Provider thì mình hiểu được lập trình viên họ đã vá lỗi như thế nào? giả sử không có đoạn code vá đó thì mình sẽ phải khai thác như thế nào?  
__7.1.3 ga4__[1]  
{{< highlight java "linenos=table,hl_lines=127,linenostart=112" >}}
        protected String buildURL(
		DDMDataProviderRequest ddmDataProviderRequest,
		DDMRESTDataProviderSettings ddmRESTDataProviderSettings) {

		Map<String, String> pathParameters = getPathParameters(
			ddmDataProviderRequest, ddmRESTDataProviderSettings);

		String url = ddmRESTDataProviderSettings.url();

		for (Map.Entry<String, String> pathParameter :
				pathParameters.entrySet()) {

			url = StringUtil.replaceFirst(
				url, String.format("{%s}", pathParameter.getKey()),
				HtmlUtil.escapeURL(pathParameter.getValue()));
		}

		return url;
	}
{{< / highlight >}}  
__7.1.2 ga3__[2]  
{{< highlight java "linenos=table,hl_lines=127,linenostart=112" >}}
protected String buildURL(
		DDMDataProviderRequest ddmDataProviderRequest,
		DDMRESTDataProviderSettings ddmRESTDataProviderSettings) {

		Map<String, String> pathParameters = getPathParameters(
			ddmDataProviderRequest, ddmRESTDataProviderSettings);

		String url = ddmRESTDataProviderSettings.url();

		for (Map.Entry<String, String> pathParameter :
				pathParameters.entrySet()) {

			url = StringUtil.replaceFirst(
				url, String.format("{%s}", pathParameter.getKey()),
				pathParameter.getValue());
		}

		return url;
	}
{{< / highlight >}}  

# Tìm vị trí lỗi
Đây là một bước khó. Hiểu được cách vá nhưng nhận định lỗi ở đoạn code nào và khai thác thực sự khó nếu như bản vá không quá chi tiết. May mắn là class này khá dễ hiểu.  
Class này nhiệm vụ tạo 1 URL và request đến URL đó, thế mới bị lỗi SSRF là đúng rồi vì tôi xem từ trên xuống dưới hầu như không có bước filter hay sanitizer nào cả.   
{{< highlight java "linenos=table,linenostart=295" >}}
HttpResponse httpResponse = httpRequest.send();
DocumentContext documentContext = JsonPath.parse(httpResponse.bodyText());
{{< / highlight >}}  

# Tìm cách sử dụng module DDM data provider 
Module này là một thành phần của chức năng tạo form trong quản trị admin, có thể xem chi tiết ở tài liệu tham khảo [3], [4]. Tôi sẽ tóm tắt sơ qua các bước làm
Bước 1: truy cập vào form applications trong site liferay (Liferay > contents & data > forms)  
Bước 2: Chọn ở menu bên phải Data Providers.  
Bước 3: Tạo mới 1 REST Data Provider  
Bước 4: Tạo bất kì giá trị này với URL là url để SSRF
Bước 5: Lưu lại.  
Tạo 1 form đính kèm data provider vào  
Bước 1: Quay về trang trước, tạo 1 form  
Bước 2: Tạo 1 element bằng cách kéo `Select from list`
Bước 3: Trong element vừa tạo, chọn data provider và output provider là data provider vừa tạo ở trên.
Bước 4: Publish form và lấy url. Mỗi lần truy cập url đó thì sẽ khảo tạo 1 request đến host của mình.




# Tài liệu tham khảo  
1. [Mã nguồn class DDMRESTDataProvider version 7.1.3 ga4](https://github.com/liferay/liferay-portal/blob/7.1.3-ga4/modules/apps/dynamic-data-mapping/dynamic-data-mapping-data-provider-impl/src/main/java/com/liferay/dynamic/data/mapping/data/provider/internal/rest/DDMRESTDataProvider.java)   
2. [Mã nguồn class DDMRESTDataProvider version 7.1.2 ga3](https://github.com/liferay/liferay-portal/blob/7.1.2-ga3/modules/apps/dynamic-data-mapping/dynamic-data-mapping-data-provider-impl/src/main/java/com/liferay/dynamic/data/mapping/data/provider/internal/rest/DDMRESTDataProvider.java)
3. [Data Providers](https://portal.liferay.dev/docs/7-1/user/-/knowledge_base/u/data-providers)
4. [Creating advanced forms](https://portal.liferay.dev/docs/7-0/user/-/knowledge_base/u/creating-advanced-forms)
