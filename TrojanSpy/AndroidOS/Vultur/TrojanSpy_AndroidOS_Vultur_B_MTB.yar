
rule TrojanSpy_AndroidOS_Vultur_B_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/Vultur.B!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {53 63 72 65 65 6e 52 65 63 6f 72 64 53 65 72 76 69 63 65 } //01 00 
		$a_01_1 = {4d 65 64 69 61 55 70 6c 6f 61 64 57 6f 72 6b 65 72 } //01 00 
		$a_01_2 = {6e 73 74 61 72 74 5f 76 6e 63 } //01 00 
		$a_01_3 = {55 6e 6c 6f 63 6b 53 63 72 65 65 6e 43 61 70 74 75 72 65 41 63 74 69 76 69 74 79 } //01 00 
		$a_01_4 = {4d 65 73 73 61 67 69 6e 67 53 65 72 76 69 63 65 } //01 00 
		$a_01_5 = {4e 67 72 6f 6b 44 6f 77 6e 6c 6f 61 64 57 6f 72 6b 65 72 } //00 00 
	condition:
		any of ($a_*)
 
}