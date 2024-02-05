
rule Trojan_Win32_Redline_GNR_MTB{
	meta:
		description = "Trojan:Win32/Redline.GNR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_03_0 = {0f b6 06 83 c4 08 0f b6 0f 8b 74 24 10 03 c8 0f b6 c1 8a 84 04 90 01 04 30 85 90 01 04 45 81 fd 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Redline_GNR_MTB_2{
	meta:
		description = "Trojan:Win32/Redline.GNR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_03_0 = {03 c7 89 45 90 01 01 8b c7 d3 e8 8b 4d 90 01 01 c7 05 90 01 04 ee 3d ea f4 89 45 90 01 01 8d 45 90 01 01 e8 90 01 04 8b 45 90 01 01 31 45 90 01 01 81 3d 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Redline_GNR_MTB_3{
	meta:
		description = "Trojan:Win32/Redline.GNR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_03_0 = {8d 04 37 d3 ee 8b 4c 24 90 01 01 89 44 24 90 01 01 8d 44 24 90 01 01 89 74 24 90 01 01 c7 05 90 01 04 ee 3d ea f4 e8 90 01 04 8b 44 24 90 01 01 31 44 24 90 01 01 81 3d 90 01 04 e6 09 00 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}