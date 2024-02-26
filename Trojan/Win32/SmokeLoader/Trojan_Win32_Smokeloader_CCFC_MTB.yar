
rule Trojan_Win32_Smokeloader_CCFC_MTB{
	meta:
		description = "Trojan:Win32/Smokeloader.CCFC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {33 ff 89 74 24 90 01 01 89 3d 90 01 04 8b 44 24 90 01 01 01 05 90 01 04 a1 90 01 04 89 44 24 90 01 01 89 7c 24 90 01 01 8b 44 24 90 01 01 01 44 24 90 01 01 8b 44 24 90 01 01 33 44 24 90 01 01 89 44 24 90 01 01 8b 4c 24 90 01 01 89 4c 24 90 01 01 8b 44 24 90 01 01 29 44 24 90 01 01 8b 4c 24 90 01 01 8b c1 c1 e0 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}