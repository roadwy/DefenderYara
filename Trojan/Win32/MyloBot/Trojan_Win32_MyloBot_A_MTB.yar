
rule Trojan_Win32_MyloBot_A_MTB{
	meta:
		description = "Trojan:Win32/MyloBot.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 04 00 00 "
		
	strings :
		$a_03_0 = {0f b6 32 33 f0 81 e6 90 01 04 c1 e8 90 01 01 33 04 b5 90 01 04 42 49 90 00 } //2
		$a_01_1 = {4d 6f 7a 69 6c 6c 61 2f 34 2e 30 20 28 63 6f 6d 70 61 74 69 62 6c 65 3b 20 4d 53 49 45 20 38 2e 30 3b 20 57 69 6e 64 6f 77 73 20 4e 54 20 35 2e 31 3b 20 54 72 69 64 65 6e 74 2f 34 2e 30 29 } //2 Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/4.0)
		$a_01_2 = {43 6f 6e 74 65 6e 74 2d 54 79 70 65 3a 20 61 70 70 6c 69 63 61 74 69 6f 6e 2f 78 2d 77 77 77 2d 66 6f 72 6d 2d 75 72 6c 65 6e 63 6f 64 65 64 } //2 Content-Type: application/x-www-form-urlencoded
		$a_01_3 = {48 54 54 50 2f 31 2e 30 20 32 30 30 } //2 HTTP/1.0 200
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2) >=8
 
}