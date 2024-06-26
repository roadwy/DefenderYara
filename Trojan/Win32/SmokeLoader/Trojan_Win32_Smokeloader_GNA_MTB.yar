
rule Trojan_Win32_Smokeloader_GNA_MTB{
	meta:
		description = "Trojan:Win32/Smokeloader.GNA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_03_0 = {8b d7 d3 ea 8d 04 3b 89 45 90 01 01 c7 05 90 01 04 ee 3d ea f4 03 55 90 01 01 8b 45 90 01 01 31 45 90 01 01 33 55 90 01 01 89 55 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Smokeloader_GNA_MTB_2{
	meta:
		description = "Trojan:Win32/Smokeloader.GNA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_03_0 = {8d 04 33 d3 ee 89 45 90 01 01 c7 05 90 01 04 ee 3d ea f4 03 75 90 01 01 8b 45 90 01 01 31 45 90 01 01 33 75 90 01 01 81 3d 90 01 08 89 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Smokeloader_GNA_MTB_3{
	meta:
		description = "Trojan:Win32/Smokeloader.GNA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_03_0 = {03 d6 d3 ee 8b cd 8d 44 24 90 01 01 89 54 24 90 01 01 89 74 24 90 01 01 c7 05 90 01 04 ee 3d ea f4 e8 90 01 04 8b 44 24 90 01 01 31 44 24 90 01 01 81 3d 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Smokeloader_GNA_MTB_4{
	meta:
		description = "Trojan:Win32/Smokeloader.GNA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_03_0 = {62 d4 ec 26 b8 90 01 04 f7 64 24 90 01 01 8b 44 24 90 01 01 81 6c 24 90 01 01 46 47 2e 63 81 44 24 90 01 01 d0 50 3e 7e 81 6c 24 90 01 01 74 f6 20 40 81 44 24 90 01 01 6d 8d f3 1b 81 44 24 90 01 01 1a 8d 4c 3c 81 6c 24 90 01 01 a7 1e 7a 2c 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}