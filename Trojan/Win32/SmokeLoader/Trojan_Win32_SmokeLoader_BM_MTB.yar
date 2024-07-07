
rule Trojan_Win32_SmokeLoader_BM_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.BM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 45 f8 8b 4d f0 8d 3c 10 8b c2 d3 e8 89 7d e8 89 35 90 02 04 03 45 c8 33 c7 31 45 fc 8b 45 f4 89 45 e4 8b 45 fc 29 45 e4 8b 45 e4 89 45 f4 8b 45 c4 29 45 f8 ff 4d d8 0f 90 00 } //2
		$a_01_1 = {81 00 e1 34 ef c6 c3 29 08 c3 01 08 c3 } //2
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}