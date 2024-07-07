
rule Trojan_Win32_Redline_GNQ_MTB{
	meta:
		description = "Trojan:Win32/Redline.GNQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b c6 83 e0 03 8a 98 90 01 04 32 9e 90 01 04 e8 90 01 04 50 e8 90 01 04 88 9e 90 01 04 46 59 81 fe 90 00 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}
rule Trojan_Win32_Redline_GNQ_MTB_2{
	meta:
		description = "Trojan:Win32/Redline.GNQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_03_0 = {ff 80 34 1e 90 01 01 68 90 01 04 68 90 01 04 e8 90 01 04 50 e8 90 01 04 80 04 1e 90 00 } //10
		$a_03_1 = {ff 80 04 1e 90 01 01 83 c4 30 46 3b f7 0f 82 90 00 } //10
	condition:
		((#a_03_0  & 1)*10+(#a_03_1  & 1)*10) >=20
 
}
rule Trojan_Win32_Redline_GNQ_MTB_3{
	meta:
		description = "Trojan:Win32/Redline.GNQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {03 ce 89 4c 24 90 01 01 8b 4c 24 90 01 01 d3 ee 8b 4c 24 90 01 01 8d 44 24 90 01 01 c7 05 90 01 04 ee 3d ea f4 89 74 24 90 01 01 e8 90 01 04 8b 44 24 90 01 01 31 44 24 90 01 01 81 3d 90 01 04 e6 09 00 00 90 00 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}