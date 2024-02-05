
rule Trojan_Win32_Smokeloader_GHO_MTB{
	meta:
		description = "Trojan:Win32/Smokeloader.GHO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_03_0 = {8d 0c 03 c1 e8 90 01 01 89 44 24 90 01 01 8b 44 24 90 01 01 01 44 24 90 01 01 8b 44 24 90 01 01 33 c1 31 44 24 90 01 01 81 3d 90 01 04 ba 05 00 00 89 44 24 90 01 01 c7 05 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}