
rule Trojan_Win32_RedLineStealer_CG_MTB{
	meta:
		description = "Trojan:Win32/RedLineStealer.CG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {8a 06 46 88 07 47 bb 02 00 00 00 00 d2 75 05 8a 16 46 10 d2 73 ea } //01 00 
		$a_00_1 = {89 c0 29 c7 8a 07 5f 88 07 47 bb 02 00 00 00 eb 99 } //01 00 
		$a_81_2 = {53 74 6f 72 65 64 20 70 61 73 73 77 6f 72 64 20 69 73 20 63 6f 72 72 75 70 74 } //01 00 
		$a_81_3 = {53 65 6c 65 63 74 20 76 69 72 75 73 20 73 63 61 6e 6e 65 72 } //00 00 
	condition:
		any of ($a_*)
 
}