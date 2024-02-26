
rule Trojan_Win32_Smokeloader_MB_MTB{
	meta:
		description = "Trojan:Win32/Smokeloader.MB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_03_0 = {8b 44 24 14 8b 4c 24 10 c1 e8 05 03 44 24 34 33 cb c7 05 90 01 08 c7 05 90 01 08 89 44 24 18 89 4c 24 10 8b 44 24 18 31 44 24 10 2b 74 24 10 81 c7 47 86 c8 61 4d 0f 85 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}