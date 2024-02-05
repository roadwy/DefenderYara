
rule Trojan_Win32_Amadey_GGO_MTB{
	meta:
		description = "Trojan:Win32/Amadey.GGO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {d3 e8 89 44 24 14 8b 44 24 90 01 01 01 44 24 14 8b 44 24 24 31 44 24 90 01 01 8b 4c 24 10 33 4c 24 14 8d 44 24 2c 89 4c 24 10 e8 90 01 04 8d 44 24 90 01 01 e8 90 01 04 83 eb 01 0f 85 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}