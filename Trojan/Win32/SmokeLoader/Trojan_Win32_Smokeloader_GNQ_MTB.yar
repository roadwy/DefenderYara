
rule Trojan_Win32_Smokeloader_GNQ_MTB{
	meta:
		description = "Trojan:Win32/Smokeloader.GNQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_03_0 = {8b c6 c1 e8 90 01 01 03 44 24 90 01 01 89 2d 90 01 04 33 c1 8b 4c 24 90 01 01 03 ce 33 c1 2b f8 8b d7 c1 e2 90 01 01 81 3d 90 01 08 89 44 24 90 01 01 89 54 24 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}