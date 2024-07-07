
rule Trojan_Win32_Redline_GNW_MTB{
	meta:
		description = "Trojan:Win32/Redline.GNW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {ff d7 80 b6 90 01 05 53 53 53 ff d7 80 86 90 01 05 53 53 53 ff d7 80 86 90 01 05 46 81 fe 90 00 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}
rule Trojan_Win32_Redline_GNW_MTB_2{
	meta:
		description = "Trojan:Win32/Redline.GNW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b c6 c1 e8 90 01 01 03 44 24 90 01 01 c7 05 90 01 08 33 c1 8d 0c 2e 33 c1 2b f8 8b d7 c1 e2 90 01 01 81 3d 90 01 08 89 44 24 90 01 01 89 54 24 90 00 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}