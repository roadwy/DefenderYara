
rule Trojan_Win32_SmokeLdr_GD_MTB{
	meta:
		description = "Trojan:Win32/SmokeLdr.GD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 0a 00 "
		
	strings :
		$a_02_0 = {30 01 42 3b 54 24 90 0a 1e 00 8b 44 24 90 01 01 8d 0c 02 90 18 a1 90 01 04 69 c0 90 01 04 05 90 01 04 a3 90 01 04 0f b7 05 90 01 04 25 90 01 04 c3 90 00 } //0a 00 
		$a_02_1 = {88 14 0f 3d 03 02 00 00 75 90 01 01 89 35 90 01 04 41 3b c8 72 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}