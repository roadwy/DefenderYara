
rule Trojan_Win32_Smokeloader_IK_MTB{
	meta:
		description = "Trojan:Win32/Smokeloader.IK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_03_0 = {56 57 33 c9 bf 7e 07 00 00 8b c1 83 e0 03 8a 80 90 01 04 30 81 90 01 04 41 3b cf 72 ea 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Smokeloader_IK_MTB_2{
	meta:
		description = "Trojan:Win32/Smokeloader.IK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b c6 c1 e8 90 01 01 c7 05 90 01 08 89 45 90 01 01 8b 45 90 01 01 01 45 90 01 01 8b c6 c1 e0 90 01 01 03 45 f0 8d 0c 32 33 c1 33 45 90 01 01 2b f8 81 3d 90 01 08 74 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}