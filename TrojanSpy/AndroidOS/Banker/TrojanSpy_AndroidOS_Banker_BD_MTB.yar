
rule TrojanSpy_AndroidOS_Banker_BD_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/Banker.BD!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {69 6e 74 65 72 63 65 70 74 4e 6f 74 69 66 69 63 61 74 69 6f 6e } //01 00 
		$a_01_1 = {73 65 6e 64 4b 65 79 6c 6f 67 73 } //01 00 
		$a_01_2 = {64 79 6e 61 6d 69 63 73 6f 63 6b 65 74 } //01 00 
		$a_01_3 = {44 65 76 69 63 65 41 64 6d 69 6e 41 64 64 } //01 00 
		$a_01_4 = {65 6e 61 62 6c 65 64 5f 61 63 63 65 73 73 69 62 69 6c 69 74 79 5f 73 65 72 76 69 63 65 73 } //01 00 
		$a_01_5 = {69 73 44 65 62 75 67 67 65 72 43 6f 6e 6e 65 63 74 65 64 } //00 00 
	condition:
		any of ($a_*)
 
}