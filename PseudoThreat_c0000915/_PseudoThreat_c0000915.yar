
rule _PseudoThreat_c0000915{
	meta:
		description = "!PseudoThreat_c0000915,SIGNATURE_TYPE_ARHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {6a 04 68 00 10 00 00 68 b0 36 00 00 6a 00 ff 15 } //01 00 
		$a_03_1 = {6a 04 68 00 10 00 00 68 9a 42 0f 00 6a 00 90 02 03 ff 15 90 00 } //01 00 
		$a_03_2 = {6a 04 68 00 10 00 00 68 10 27 00 00 6a 00 90 02 03 ff 15 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}