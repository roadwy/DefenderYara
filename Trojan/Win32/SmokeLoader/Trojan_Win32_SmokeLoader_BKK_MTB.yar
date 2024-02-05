
rule Trojan_Win32_SmokeLoader_BKK_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.BKK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b d6 d3 ea 8b 4c 24 90 01 01 8d 44 24 90 01 01 c7 05 90 01 08 89 54 24 90 01 01 e8 90 01 04 8b 44 24 90 01 01 31 44 24 90 01 01 81 3d 90 01 08 75 90 00 } //01 00 
		$a_03_1 = {01 44 24 1c 8b 44 24 90 01 01 89 44 24 90 01 01 8b 4c 24 90 01 01 33 4c 24 90 01 01 8b c7 c1 e8 90 01 01 51 03 c5 50 8d 54 24 90 01 01 52 89 4c 24 90 01 01 e8 90 01 04 2b 74 24 90 01 01 89 74 24 90 01 01 8b 44 24 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}