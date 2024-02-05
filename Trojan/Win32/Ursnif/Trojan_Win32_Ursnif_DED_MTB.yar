
rule Trojan_Win32_Ursnif_DED_MTB{
	meta:
		description = "Trojan:Win32/Ursnif.DED!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {8b 4c 24 14 8b c7 d3 e0 8b cf c1 e9 05 03 4c 24 2c 03 44 24 28 89 15 90 01 04 33 c1 8b 4c 24 18 03 cf 33 c1 8b 0d 90 01 04 2b e8 90 00 } //01 00 
		$a_02_1 = {8b 5d f8 8b d3 8b 4d fc 8b c3 83 25 90 01 04 00 d3 e2 03 55 e4 c1 e8 05 03 45 e0 33 d0 8d 04 1e 33 d0 2b fa 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}