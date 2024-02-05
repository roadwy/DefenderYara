
rule Trojan_Win32_Ursnif_V_MTB{
	meta:
		description = "Trojan:Win32/Ursnif.V!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {8b 45 f8 30 1c 06 46 3b f7 7c 90 09 39 00 8b 0d 90 01 04 69 c9 90 01 04 89 0d 90 01 04 81 05 90 01 08 81 3d 90 01 08 0f b7 1d 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Ursnif_V_MTB_2{
	meta:
		description = "Trojan:Win32/Ursnif.V!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {2b c7 8d 04 45 90 01 04 2b c6 0f b7 d8 8b 6c 24 90 01 01 8b 44 24 90 01 01 03 e9 8b 74 24 90 01 01 8b cf 13 c2 89 2d 90 01 04 a3 90 01 04 69 c3 90 01 04 8b 16 81 c2 90 01 04 89 16 89 15 90 01 04 2b c8 0f b7 d9 8b d3 8d 72 1c 69 c6 90 01 04 3d 90 01 04 76 0e 90 00 } //01 00 
		$a_03_1 = {03 c7 0f b7 e8 8b c5 2b c7 05 90 01 04 0f b7 c8 89 4c 24 90 01 01 83 7c 24 90 01 02 0f 83 9e 00 00 00 90 00 } //00 00 
		$a_00_2 = {5d } //04 00 
	condition:
		any of ($a_*)
 
}