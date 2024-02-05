
rule PWS_Win32_Codtree_gen_A{
	meta:
		description = "PWS:Win32/Codtree.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,05 00 04 00 08 00 00 01 00 "
		
	strings :
		$a_01_0 = {68 6c 6c 75 42 e8 } //01 00 
		$a_01_1 = {68 65 74 75 43 e8 } //01 00 
		$a_01_2 = {68 5f 72 61 46 e8 } //01 00 
		$a_01_3 = {68 61 6c 5a 46 e8 } //01 00 
		$a_01_4 = {68 50 58 46 46 e8 } //01 00 
		$a_01_5 = {68 58 70 74 46 e8 } //01 00 
		$a_01_6 = {68 74 72 6d 53 e8 } //02 00 
		$a_01_7 = {c6 06 0d 46 c6 06 0a 46 } //00 00 
	condition:
		any of ($a_*)
 
}