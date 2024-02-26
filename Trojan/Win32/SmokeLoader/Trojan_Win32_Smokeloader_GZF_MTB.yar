
rule Trojan_Win32_Smokeloader_GZF_MTB{
	meta:
		description = "Trojan:Win32/Smokeloader.GZF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 05 00 "
		
	strings :
		$a_03_0 = {6a 40 52 51 a3 90 01 04 ff d0 81 c4 90 00 } //05 00 
		$a_03_1 = {73 69 c6 05 90 01 04 2e c7 05 90 01 04 6d 67 33 32 c7 05 90 01 04 64 6c 6c 00 a2 90 01 04 ff 15 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Smokeloader_GZF_MTB_2{
	meta:
		description = "Trojan:Win32/Smokeloader.GZF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_03_0 = {8d 04 3b 89 45 90 01 01 8b 45 90 01 01 c1 e8 90 01 01 89 45 90 01 01 8b 45 90 01 01 01 45 90 01 01 8b 45 90 01 01 33 d2 c7 05 90 01 04 ee 3d ea f4 89 45 90 01 01 89 55 90 01 01 8b 45 90 01 01 01 45 90 01 01 8b 45 90 01 01 31 45 90 01 01 8b 45 90 01 01 33 45 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}