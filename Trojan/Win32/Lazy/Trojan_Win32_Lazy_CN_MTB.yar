
rule Trojan_Win32_Lazy_CN_MTB{
	meta:
		description = "Trojan:Win32/Lazy.CN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 08 00 00 "
		
	strings :
		$a_01_0 = {f3 a4 83 ec 04 c7 04 24 70 55 5b 5a 83 c4 04 57 97 5f 90 89 c0 83 c4 04 87 4c 24 fc 57 83 c4 04 90 8b 34 24 83 c4 04 c7 44 24 fc 53 f0 e1 84 53 83 c4 04 8b 3c 24 83 c4 04 c7 44 24 fc 4e 67 7c e8 } //3
		$a_01_1 = {f3 a4 83 ec 04 c7 04 24 f0 07 81 98 83 c4 04 57 97 5f c7 44 24 fc 42 b1 99 5e 68 36 cf 90 29 83 c4 04 59 56 83 c4 04 83 ec 04 c7 04 24 74 38 1d 52 83 c4 04 83 c4 04 8b 74 24 fc } //3
		$a_01_2 = {f3 a4 90 57 58 89 c0 83 ec 04 c7 04 24 1a 91 e7 55 83 c4 04 83 c4 04 8b 4c 24 fc 90 57 83 c4 04 83 c4 04 87 74 24 fc c7 44 24 fc ca d3 85 fb 53 83 c4 04 8b 3c 24 83 c4 04 57 83 c4 04 c9 } //3
		$a_01_3 = {f3 a4 c7 44 24 fc 20 95 69 9d 89 f8 89 c0 c7 44 24 fc 37 9c 8c 26 83 c4 04 87 4c 24 fc c7 44 24 fc 29 b6 4b e4 89 c0 87 34 24 83 c4 04 c7 44 24 fc fb 46 14 00 } //3
		$a_01_4 = {78 6d 74 75 7a 79 73 64 6f 62 } //2 xmtuzysdob
		$a_01_5 = {67 63 64 75 66 70 6d 6c 76 6b 6e } //2 gcdufpmlvkn
		$a_01_6 = {75 78 6f 6a 70 67 76 63 6d 62 66 } //2 uxojpgvcmbf
		$a_01_7 = {68 6a 6f 74 6d 77 78 79 6b 6c 67 7a } //2 hjotmwxyklgz
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*3+(#a_01_2  & 1)*3+(#a_01_3  & 1)*3+(#a_01_4  & 1)*2+(#a_01_5  & 1)*2+(#a_01_6  & 1)*2+(#a_01_7  & 1)*2) >=5
 
}