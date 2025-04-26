
rule Trojan_Win32_Startpage_XQ{
	meta:
		description = "Trojan:Win32/Startpage.XQ,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {2e 32 32 71 69 2e 63 6f 6d 2f 74 61 6f 62 61 6f 2e 68 74 6d 6c } //1 .22qi.com/taobao.html
		$a_01_1 = {61 48 52 30 63 44 6f 76 4c 33 64 33 64 79 34 79 4d 6a 4e 73 59 53 35 6a 62 32 30 } //1 aHR0cDovL3d3dy4yMjNsYS5jb20
		$a_01_2 = {61 48 52 30 63 44 6f 76 4c 33 64 33 64 79 34 79 4d 6e 46 70 4c 6d 4e 76 62 53 39 30 59 57 39 69 59 57 38 75 61 48 52 74 62 41 3d 3d } //1 aHR0cDovL3d3dy4yMnFpLmNvbS90YW9iYW8uaHRtbA==
		$a_01_3 = {25 b0 ae 25 b0 ae 25 c6 e6 25 cd f8 25 d6 b7 25 b5 bc 25 ba bd 5b 25 57 77 25 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}