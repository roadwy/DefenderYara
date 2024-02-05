
rule Trojan_Win32_SmokeLdr_GI_MTB{
	meta:
		description = "Trojan:Win32/SmokeLdr.GI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 0a 00 "
		
	strings :
		$a_02_0 = {30 0c 3e 46 3b f3 7c 90 0a 28 00 a1 90 01 04 69 c0 90 01 04 05 90 01 04 a3 90 01 04 8a 0d 90 00 } //01 00 
		$a_02_1 = {8a 04 0f 88 04 0e 81 fa 03 02 00 00 75 90 01 01 89 90 01 05 41 3b 90 01 01 72 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}