
rule Trojan_Win32_SmokeLoader_MYB_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.MYB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {03 c8 89 4d e8 8b 4d f0 d3 e8 c7 05 90 01 04 ee 3d ea f4 03 c3 8b c8 8b 45 e8 31 45 fc 33 4d fc 81 3d 90 01 04 13 02 00 00 89 4d e8 75 90 00 } //1
		$a_03_1 = {d3 e8 03 c7 33 c2 31 45 fc 8b 45 fc 29 45 f4 8d 45 ec e8 90 01 04 ff 4d e4 0f 85 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}