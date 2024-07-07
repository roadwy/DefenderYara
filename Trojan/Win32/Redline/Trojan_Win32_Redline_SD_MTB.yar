
rule Trojan_Win32_Redline_SD_MTB{
	meta:
		description = "Trojan:Win32/Redline.SD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_03_0 = {89 c2 83 e2 90 01 01 8a 8a 90 01 04 30 0c 38 40 3b c6 72 90 00 } //10
		$a_03_1 = {03 c8 83 e1 90 01 01 0f b6 89 90 01 04 30 88 90 01 04 83 c0 90 01 01 3d 90 01 04 72 90 00 } //10
	condition:
		((#a_03_0  & 1)*10+(#a_03_1  & 1)*10) >=20
 
}
rule Trojan_Win32_Redline_SD_MTB_2{
	meta:
		description = "Trojan:Win32/Redline.SD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {41 85 04 51 a8 22 ba 90 01 04 b3 6c f6 3d 90 01 04 c9 60 00 d0 09 e5 8d 8d 90 01 04 9a 90 01 04 7b c7 09 3d 90 01 04 e0 96 60 72 f6 33 d3 66 3b e3 f9 e9 10 87 03 00 88 14 39 e9 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}