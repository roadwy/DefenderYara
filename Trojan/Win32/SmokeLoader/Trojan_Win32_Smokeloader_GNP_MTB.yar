
rule Trojan_Win32_Smokeloader_GNP_MTB{
	meta:
		description = "Trojan:Win32/Smokeloader.GNP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_03_0 = {8b c1 c1 e8 90 01 01 03 44 24 90 01 01 03 d5 33 c2 03 cf 33 c1 2b f0 8b d6 c1 e2 90 01 01 89 44 24 90 01 01 c7 05 90 01 08 89 54 24 90 01 01 8b 44 24 90 01 01 01 44 24 90 01 01 81 3d 90 01 08 8d 1c 37 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}