
rule Trojan_Win32_RedLine_MBCQ_MTB{
	meta:
		description = "Trojan:Win32/RedLine.MBCQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {2d a7 00 00 00 88 44 24 1f 0f b6 4c 24 1f 31 c0 29 c8 88 44 24 1f 0f b6 44 24 1f 83 f0 ff 88 44 24 1f 8b 4c 24 20 0f b6 44 24 1f 01 c8 88 44 24 1f 0f b6 44 24 1f c1 f8 01 0f b6 4c 24 1f c1 e1 07 09 c8 88 44 24 1f 8a 4c 24 1f } //1
		$a_01_1 = {65 6d 7a 65 75 75 6d 76 67 77 74 67 76 64 64 63 64 7a 77 71 72 71 78 62 64 77 67 70 6a 76 77 73 6b 75 6f } //1 emzeuumvgwtgvddcdzwqrqxbdwgpjvwskuo
		$a_01_2 = {62 6c 7a 64 6f 78 6c 74 70 74 6a 73 71 78 61 69 74 65 64 61 6f 70 75 6f 70 74 65 7a 65 6a 71 6e 73 76 63 6a 78 69 6d 76 70 6f 71 61 67 69 76 78 64 66 71 6a 72 74 65 65 6d 71 69 70 68 65 75 6c 76 64 79 74 61 78 6b 63 78 71 75 7a 77 } //1 blzdoxltptjsqxaitedaopuoptezejqnsvcjximvpoqagivxdfqjrteemqipheulvdytaxkcxquzw
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}