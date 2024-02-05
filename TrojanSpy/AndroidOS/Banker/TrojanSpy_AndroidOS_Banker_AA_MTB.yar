
rule TrojanSpy_AndroidOS_Banker_AA_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/Banker.AA!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {62 61 63 6b 75 70 53 4d 53 } //01 00 
		$a_01_1 = {75 70 6c 6f 61 64 4d 6f 62 69 6c 65 49 6e 66 6f } //01 00 
		$a_01_2 = {72 65 75 70 6c 6f 61 64 43 61 6c 6c } //01 00 
		$a_01_3 = {42 61 6e 6b 44 65 74 61 69 6c 41 63 74 69 76 69 74 79 } //01 00 
		$a_01_4 = {74 72 61 63 65 5f 70 61 73 73 77 6f 72 64 } //01 00 
		$a_01_5 = {4d 6f 62 6c 69 65 43 6f 6e 74 72 6f 6c 6c 65 72 } //00 00 
	condition:
		any of ($a_*)
 
}