
rule Trojan_Win32_Smokeloader_GNL_MTB{
	meta:
		description = "Trojan:Win32/Smokeloader.GNL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 0a 00 "
		
	strings :
		$a_03_0 = {33 d7 31 54 24 90 01 01 8b 44 24 90 01 01 29 44 24 90 01 01 8b 3d 90 01 04 81 ff 90 00 } //0a 00 
		$a_03_1 = {03 d5 33 c2 03 cb 33 c1 2b f0 8b d6 c1 e2 90 01 01 89 44 24 90 01 01 c7 05 90 01 08 89 54 24 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}