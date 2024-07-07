
rule TrojanDownloader_Win32_Stration_SW{
	meta:
		description = "TrojanDownloader:Win32/Stration.SW,SIGNATURE_TYPE_PEHSTR,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 3a 2f 2f 62 65 72 75 69 6a 69 6e 64 65 67 75 6e 68 61 64 65 73 75 6e 2e 63 6f 6d 2f 6b 74 6d 63 68 65 63 6b 2e 65 78 65 } //1 http://beruijindegunhadesun.com/ktmcheck.exe
		$a_01_1 = {47 45 54 20 2f 6b 74 6d 63 68 65 63 6b 2e 65 78 65 20 48 54 54 50 2f 31 2e 31 } //1 GET /ktmcheck.exe HTTP/1.1
		$a_01_2 = {55 73 65 72 2d 41 67 65 6e 74 3a 20 4d 6f 7a 69 6c 6c 61 2f 34 2e 30 20 28 63 6f 6d 70 61 74 69 62 6c 65 3b 20 4d 53 49 45 20 36 2e 30 3b 20 57 69 6e 64 6f 77 73 20 4e 54 20 35 2e 31 29 } //1 User-Agent: Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)
		$a_01_3 = {48 6f 73 74 3a 20 62 65 72 75 69 6a 69 6e 64 65 67 75 6e 68 61 64 65 73 75 6e 2e 63 6f 6d } //1 Host: beruijindegunhadesun.com
		$a_01_4 = {50 72 61 67 6d 61 3a 20 6e 6f 2d 63 61 63 68 65 } //1 Pragma: no-cache
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}