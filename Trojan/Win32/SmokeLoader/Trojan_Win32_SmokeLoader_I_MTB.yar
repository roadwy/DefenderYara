
rule Trojan_Win32_SmokeLoader_I_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.I!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b c6 c1 e8 05 03 44 24 24 c7 05 90 01 04 19 36 6b ff 33 c3 31 44 24 10 c7 05 90 01 04 ff ff ff ff 8b 44 24 10 29 44 24 14 81 c7 47 86 c8 61 4d 0f 85 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_SmokeLoader_I_MTB_2{
	meta:
		description = "Trojan:Win32/SmokeLoader.I!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_01_0 = {31 45 fc d3 ef 03 7d d4 81 3d f4 ec 41 02 } //2
		$a_03_1 = {31 7d fc 8b 45 fc 29 45 f4 81 c3 90 01 04 ff 4d e8 0f 90 00 } //2
		$a_01_2 = {03 7d e4 8b 45 e0 31 45 fc 33 7d fc 81 3d f4 ec 41 02 } //2
	condition:
		((#a_01_0  & 1)*2+(#a_03_1  & 1)*2+(#a_01_2  & 1)*2) >=6
 
}