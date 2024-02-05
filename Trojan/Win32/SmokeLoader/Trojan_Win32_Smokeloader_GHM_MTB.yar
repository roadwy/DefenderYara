
rule Trojan_Win32_Smokeloader_GHM_MTB{
	meta:
		description = "Trojan:Win32/Smokeloader.GHM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_03_0 = {8b c7 c1 e8 90 01 01 03 c5 33 44 24 90 01 01 33 c8 8d 44 24 90 01 01 89 4c 24 90 01 01 e8 90 01 04 81 44 24 90 01 01 47 86 c8 61 83 ea 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Smokeloader_GHM_MTB_2{
	meta:
		description = "Trojan:Win32/Smokeloader.GHM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_03_0 = {8b c7 c1 e8 90 01 01 03 c5 33 44 24 90 01 01 33 c8 8d 44 24 90 01 01 89 4c 24 90 01 01 e8 90 01 04 8b 44 24 90 01 01 29 44 24 90 01 01 83 ea 90 01 01 0f 85 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}