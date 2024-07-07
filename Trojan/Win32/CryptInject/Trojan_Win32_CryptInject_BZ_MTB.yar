
rule Trojan_Win32_CryptInject_BZ_MTB{
	meta:
		description = "Trojan:Win32/CryptInject.BZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8a 04 06 33 c9 8a 4d 11 32 c8 51 56 8d 4d f0 e8 90 01 04 8b 45 f0 b9 90 01 04 66 0f b6 04 06 03 45 10 69 c0 93 31 00 00 2b c8 8b 45 0c 46 89 4d 10 3b 70 f8 7c c8 90 00 } //1
		$a_01_1 = {73 65 74 20 50 41 53 53 57 44 3d 27 } //1 set PASSWD='
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
rule Trojan_Win32_CryptInject_BZ_MTB_2{
	meta:
		description = "Trojan:Win32/CryptInject.BZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {8a 8c 30 3b 2d 0b 00 8b 15 90 01 04 88 0c 32 81 3d 90 01 04 37 0d 00 00 75 90 00 } //1
		$a_02_1 = {8b c7 d3 e0 8b cf c1 e9 05 03 4d e4 03 45 d8 89 15 90 01 04 33 c1 8b 4d f0 03 cf 33 c1 29 45 f8 a1 90 01 04 3d d5 01 00 00 75 90 00 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}