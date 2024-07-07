
rule _PseudoThreat_c0000a93{
	meta:
		description = "!PseudoThreat_c0000a93,SIGNATURE_TYPE_ARHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {6a 04 68 00 10 00 00 68 b0 36 00 00 6a 00 ff 15 } //1
		$a_03_1 = {6a 04 68 00 10 00 00 68 9a 42 0f 00 6a 00 90 02 03 ff 15 90 00 } //1
		$a_03_2 = {6a 04 68 00 10 00 00 68 10 27 00 00 6a 00 90 02 03 ff 15 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}