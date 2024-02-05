
rule Trojan_Win32_Smokeloader_GHL_MTB{
	meta:
		description = "Trojan:Win32/Smokeloader.GHL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_03_0 = {8b d0 c1 e2 90 01 01 03 54 24 90 01 01 8d 0c 07 c1 e8 90 01 01 89 54 24 90 01 01 89 44 24 90 01 01 8b 44 24 90 01 01 01 44 24 90 01 01 8b 44 24 90 01 01 33 c1 31 44 24 90 01 01 81 3d 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}