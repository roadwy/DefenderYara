
rule TrojanSpy_AndroidOS_Gepew_B_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/Gepew.B!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {67 6f 6f 6b 2e 6a 6b 75 62 2e 63 6f 6d } //01 00 
		$a_01_1 = {53 4d 53 41 6c 6c 43 6f 6d 70 61 74 65 } //01 00 
		$a_01_2 = {67 65 74 50 68 6f 6e 65 43 6f 6e 74 61 63 74 73 } //01 00 
		$a_01_3 = {44 65 6c 65 74 65 43 61 6c 6c } //01 00 
		$a_01_4 = {61 75 74 6f 43 68 61 6e 67 65 41 70 70 73 } //01 00 
		$a_01_5 = {4b 52 5f 4e 48 42 61 6e 6b 2e 61 70 6b } //00 00 
	condition:
		any of ($a_*)
 
}