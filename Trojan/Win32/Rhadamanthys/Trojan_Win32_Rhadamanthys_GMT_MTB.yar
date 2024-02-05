
rule Trojan_Win32_Rhadamanthys_GMT_MTB{
	meta:
		description = "Trojan:Win32/Rhadamanthys.GMT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {d3 e8 8b 4c 24 90 01 01 c7 05 90 01 08 89 44 24 90 01 01 8d 44 24 90 01 01 e8 90 01 04 8b 44 24 90 01 01 31 44 24 90 01 01 81 3d 90 01 08 75 90 00 } //01 00 
		$a_03_1 = {8b cf 8d 44 24 90 01 01 89 54 24 90 01 01 e8 90 01 04 8b 44 24 90 01 01 31 44 24 90 01 01 8b 44 24 90 01 01 8b 4c 24 90 01 01 50 51 8d 54 24 90 01 01 52 e8 90 01 04 8b 44 24 90 01 01 29 44 24 90 01 01 81 44 24 90 01 05 83 eb 90 01 01 0f 85 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}