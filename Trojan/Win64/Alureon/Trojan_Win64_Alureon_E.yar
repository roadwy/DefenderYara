
rule Trojan_Win64_Alureon_E{
	meta:
		description = "Trojan:Win64/Alureon.E,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {65 48 8b 04 25 88 01 00 00 48 8b d3 48 89 83 90 01 01 00 00 00 48 8b 83 90 01 01 00 00 00 48 89 48 90 01 01 48 83 e8 48 49 8b cc 4c 89 60 90 01 01 c6 00 0f fe 4b 90 01 01 48 89 83 90 01 01 00 00 00 41 ff d5 3d 03 01 00 00 90 00 } //01 00 
		$a_03_1 = {80 3f 0e 0f 85 90 01 02 00 00 81 7f 18 30 d0 04 00 90 00 } //01 00 
	condition:
		any of ($a_*)
 
}