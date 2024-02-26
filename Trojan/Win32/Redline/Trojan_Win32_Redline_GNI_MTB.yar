
rule Trojan_Win32_Redline_GNI_MTB{
	meta:
		description = "Trojan:Win32/Redline.GNI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_03_0 = {8b 7d 08 33 c0 f6 17 80 2f 90 01 01 80 07 90 01 01 47 e2 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Redline_GNI_MTB_2{
	meta:
		description = "Trojan:Win32/Redline.GNI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 0a 00 "
		
	strings :
		$a_03_0 = {6a 00 ff d6 80 04 2f 90 01 01 68 90 00 } //0a 00 
		$a_03_1 = {6a 00 ff d6 80 34 2f 90 01 01 68 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Redline_GNI_MTB_3{
	meta:
		description = "Trojan:Win32/Redline.GNI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_03_0 = {8b c1 c1 e8 90 01 01 03 44 24 90 01 01 03 cb 33 c2 33 c1 2b f0 8b d6 c1 e2 90 01 01 89 44 24 90 01 01 c7 05 90 01 08 89 54 24 90 01 01 8b 44 24 90 01 01 01 44 24 90 01 01 81 3d 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}