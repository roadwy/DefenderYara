
rule Trojan_Win32_SmokeLdr_GH_MTB{
	meta:
		description = "Trojan:Win32/SmokeLdr.GH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 03 00 00 0a 00 "
		
	strings :
		$a_02_0 = {30 0c 3e 46 3b f3 7c 90 0a 28 00 a1 90 01 04 69 c0 90 01 04 05 90 01 04 a3 90 01 04 8a 0d 90 00 } //01 00 
		$a_02_1 = {3d 03 02 00 00 75 90 02 09 41 3b c8 90 0a 32 00 8b 15 90 01 04 8a 94 0a 90 01 04 8b 90 01 05 88 14 90 00 } //01 00 
		$a_02_2 = {88 0c 02 8b 0d 90 01 04 81 f9 03 02 00 00 75 90 01 01 89 90 01 05 40 3b 90 01 01 72 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}