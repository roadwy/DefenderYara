
rule TrojanDownloader_Win32_Dollflort_A{
	meta:
		description = "TrojanDownloader:Win32/Dollflort.A,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 0b 00 00 "
		
	strings :
		$a_01_0 = {46 41 53 54 2d 57 65 62 43 72 61 77 6c 65 72 2f 33 2e 38 20 28 61 74 77 2d 63 72 61 77 6c 65 72 20 61 74 20 66 61 73 74 20 64 6f 74 20 6e 6f 3b 20 68 74 74 70 3a 2f 2f 66 61 73 74 2e 6e 6f 2f 73 75 70 70 6f 72 74 2f 63 72 61 77 6c 65 72 2e 61 73 70 29 } //1 FAST-WebCrawler/3.8 (atw-crawler at fast dot no; http://fast.no/support/crawler.asp)
		$a_01_1 = {41 63 63 65 70 74 2d 45 6e 63 6f 64 69 6e 67 3a 20 64 65 66 6c 61 74 65 2c 20 67 7a 69 70 2c 20 78 2d 67 7a 69 70 2c 20 69 64 65 6e 74 69 74 79 2c 20 2a 3b 71 3d 30 } //1 Accept-Encoding: deflate, gzip, x-gzip, identity, *;q=0
		$a_01_2 = {47 6f 6f 67 6c 65 62 6f 74 2f 32 2e 31 20 28 2b 68 74 74 70 3a 2f 2f 77 77 77 2e 67 6f 6f 67 6c 65 62 6f 74 2e 63 6f 6d 2f 62 6f 74 2e 68 74 6d 6c 29 } //1 Googlebot/2.1 (+http://www.googlebot.com/bot.html)
		$a_01_3 = {54 45 3a 20 64 65 66 6c 61 74 65 2c 20 67 7a 69 70 2c 20 63 68 75 6e 6b 65 64 2c 20 69 64 65 6e 74 69 74 79 2c 20 74 72 61 69 6c 65 72 73 } //1 TE: deflate, gzip, chunked, identity, trailers
		$a_01_4 = {41 63 63 65 70 74 2d 4c 61 6e 67 75 61 67 65 3a 20 72 75 2d 52 55 2c 72 75 3b 71 3d 30 2e 39 2c 65 6e 3b 71 3d 30 2e 38 } //1 Accept-Language: ru-RU,ru;q=0.9,en;q=0.8
		$a_01_5 = {43 6f 6e 6e 65 63 74 69 6f 6e 3a 20 4b 65 65 70 2d 41 6c 69 76 65 2c 20 54 45 } //1 Connection: Keep-Alive, TE
		$a_01_6 = {44 4f 57 4e 4c 4f 41 44 5f 41 4e 44 5f 45 58 45 43 } //1 DOWNLOAD_AND_EXEC
		$a_01_7 = {53 59 4e 2f 41 43 4b } //1 SYN/ACK
		$a_01_8 = {50 4f 53 54 20 25 73 20 48 54 54 50 2f 31 2e 31 } //1 POST %s HTTP/1.1
		$a_01_9 = {47 45 54 20 25 73 20 48 54 54 50 2f 31 2e 31 } //1 GET %s HTTP/1.1
		$a_01_10 = {48 61 6c 66 4f 70 65 6e 20 41 74 74 61 63 6b } //1 HalfOpen Attack
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1) >=11
 
}