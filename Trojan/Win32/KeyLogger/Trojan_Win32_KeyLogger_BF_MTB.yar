
rule Trojan_Win32_KeyLogger_BF_MTB{
	meta:
		description = "Trojan:Win32/KeyLogger.BF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_01_0 = {34 e5 48 88 64 1d be 5a a9 ac af a6 4a be dc 59 e7 53 49 ad 35 70 8c 82 bc 3d 18 0b 96 b5 9b a2 72 ea 49 ad 78 } //4
	condition:
		((#a_01_0  & 1)*4) >=4
 
}
rule Trojan_Win32_KeyLogger_BF_MTB_2{
	meta:
		description = "Trojan:Win32/KeyLogger.BF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {31 31 00 fa 4e ad 33 99 66 cf 11 b7 0c 00 aa 00 60 d3 93 76 } //2
		$a_01_1 = {66 97 57 4b 89 74 09 a7 d3 2d ef 05 c1 40 44 13 01 14 a7 d4 63 b5 1a 5f cc 7a } //2
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}