
rule TrojanDropper_Win32_Zegost_R{
	meta:
		description = "TrojanDropper:Win32/Zegost.R,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {53 65 72 76 65 72 2e 44 61 74 00 48 61 69 00 } //01 00 
		$a_01_1 = {32 d3 02 d3 88 } //01 00 
		$a_01_2 = {2b c8 8a 14 01 8a 18 32 da 88 18 40 4e 75 f3 } //00 00 
	condition:
		any of ($a_*)
 
}