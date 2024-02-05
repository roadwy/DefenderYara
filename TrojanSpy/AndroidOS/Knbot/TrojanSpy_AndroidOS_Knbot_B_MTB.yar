
rule TrojanSpy_AndroidOS_Knbot_B_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/Knbot.B!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {73 79 73 74 65 6d 2f 62 69 6e 2f 73 63 72 65 65 6e 63 61 70 } //01 00 
		$a_01_1 = {53 4d 53 3e 20 4e 20 3a } //01 00 
		$a_00_2 = {4c 73 79 73 74 65 6d 2f 6f 70 65 72 61 74 69 6e 67 2f 64 6f 6d 69 6e 61 6e 63 65 2f 70 72 6f 6a } //01 00 
		$a_01_3 = {70 75 62 6c 69 63 2f 2f 72 65 63 6f 6f 72 64 69 6e 67 2e 77 61 76 } //01 00 
		$a_01_4 = {44 6f 20 49 20 68 61 76 65 20 72 6f 6f 74 3f } //01 00 
		$a_01_5 = {73 79 73 74 65 6d 2f 73 64 2f 74 65 6d 70 6f 72 61 72 79 2e 74 78 74 } //01 00 
		$a_01_6 = {6f 6e 4f 75 74 67 6f 69 6e 67 43 61 6c 6c 45 6e 64 65 64 } //00 00 
	condition:
		any of ($a_*)
 
}