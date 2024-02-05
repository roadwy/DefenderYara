
rule Trojan_Win32_Smokeloader_GJE_MTB{
	meta:
		description = "Trojan:Win32/Smokeloader.GJE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_03_0 = {9d 69 2b 38 c7 84 24 90 01 04 9b 17 ec 41 c7 84 24 90 01 04 81 6f 30 16 c7 84 24 90 01 04 5c 0b e9 11 c7 84 24 90 01 04 2c dc 00 48 c7 44 24 90 01 01 31 64 01 50 c7 44 24 90 01 01 24 04 8b 41 c7 84 24 90 01 04 06 51 bf 3e c7 44 24 90 01 01 4a b5 04 32 c7 84 24 90 01 04 74 4c 89 41 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}