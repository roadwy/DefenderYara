
rule TrojanClicker_Win32_Collicky_A{
	meta:
		description = "TrojanClicker:Win32/Collicky.A,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {57 45 42 43 43 5b } //01 00  WEBCC[
		$a_01_1 = {57 58 43 43 5b } //01 00  WXCC[
		$a_01_2 = {42 54 43 43 5b } //01 00  BTCC[
		$a_01_3 = {37 32 36 45 36 45 36 41 32 30 33 35 33 35 } //01 00  726E6E6A203535
		$a_01_4 = {8a 55 e7 80 f2 21 32 c2 88 45 e6 } //00 00 
		$a_00_5 = {5d 04 00 } //00 13 
	condition:
		any of ($a_*)
 
}