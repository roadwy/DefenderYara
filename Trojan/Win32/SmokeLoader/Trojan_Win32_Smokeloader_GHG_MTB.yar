
rule Trojan_Win32_Smokeloader_GHG_MTB{
	meta:
		description = "Trojan:Win32/Smokeloader.GHG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b c6 d3 e8 8b 4c 24 90 01 01 c7 05 90 01 04 ee 3d ea f4 89 44 24 90 01 01 8d 44 24 90 01 01 e8 90 01 04 8b 44 24 90 01 01 31 44 24 90 01 01 81 3d 90 00 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}
rule Trojan_Win32_Smokeloader_GHG_MTB_2{
	meta:
		description = "Trojan:Win32/Smokeloader.GHG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b c7 d3 e8 8b 4c 24 90 01 01 c7 05 90 01 04 ee 3d ea f4 89 44 24 90 01 01 8d 44 24 90 01 01 e8 90 01 04 8b 44 24 90 01 01 31 44 24 90 01 01 8b 4c 24 90 01 01 33 4c 24 90 01 01 2b d9 8b c3 90 00 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}