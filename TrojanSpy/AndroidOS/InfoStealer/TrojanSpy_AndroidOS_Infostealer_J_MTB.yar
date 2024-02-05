
rule TrojanSpy_AndroidOS_Infostealer_J_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/Infostealer.J!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {67 65 74 41 6c 6c 43 6f 6e 74 61 63 74 73 } //01 00 
		$a_01_1 = {57 6f 72 6b 4e 6f 77 } //01 00 
		$a_01_2 = {73 68 6f 77 43 6f 6e 74 61 63 74 73 } //01 00 
		$a_01_3 = {6d 73 67 42 6f 64 79 } //01 00 
		$a_01_4 = {69 73 4d 6f 62 69 6c 65 4e 4f } //01 00 
		$a_01_5 = {70 6f 73 74 44 61 74 61 } //01 00 
		$a_01_6 = {67 65 74 4c 69 73 74 } //00 00 
	condition:
		any of ($a_*)
 
}