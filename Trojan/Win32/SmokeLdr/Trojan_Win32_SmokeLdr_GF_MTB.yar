
rule Trojan_Win32_SmokeLdr_GF_MTB{
	meta:
		description = "Trojan:Win32/SmokeLdr.GF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 0a 00 "
		
	strings :
		$a_02_0 = {8b 44 24 08 8d 0c 06 e8 90 01 04 30 01 46 3b f7 90 00 } //0a 00 
		$a_02_1 = {3d 03 02 00 00 75 90 02 09 41 3b c8 90 0a 32 00 8b 15 90 01 04 8a 94 0a 90 01 04 8b 90 01 05 88 14 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}