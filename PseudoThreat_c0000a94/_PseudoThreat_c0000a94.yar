
rule _PseudoThreat_c0000a94{
	meta:
		description = "!PseudoThreat_c0000a94,SIGNATURE_TYPE_ARHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {55 8b ec 83 ec [0-04] 53 56 57 60 83 ec 04 b0 01 fe c0 75 06 81 c4 } //1
		$a_01_1 = {90 00 00 00 83 c4 04 61 60 53 66 bb 30 db 75 fc 5b 61 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}