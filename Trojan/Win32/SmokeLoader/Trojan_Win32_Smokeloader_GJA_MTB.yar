
rule Trojan_Win32_Smokeloader_GJA_MTB{
	meta:
		description = "Trojan:Win32/Smokeloader.GJA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_03_0 = {8b cb 89 44 24 90 01 01 8d 44 24 90 01 01 e8 90 01 04 8b 44 24 90 01 01 31 44 24 90 01 01 8b 4c 24 90 01 01 8b 54 24 90 01 01 51 52 8d 44 24 90 01 01 50 e8 90 01 04 8b 44 24 90 01 01 29 44 24 90 01 01 81 44 24 90 01 01 47 86 c8 61 83 ed 90 01 01 0f 85 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}