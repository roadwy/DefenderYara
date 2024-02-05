
rule TrojanSpy_AndroidOS_Banker_V_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/Banker.V!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {63 6f 6d 2f 73 73 70 6c 2f 61 70 70 2f 41 63 74 69 76 69 74 69 65 73 } //01 00 
		$a_01_1 = {70 67 69 6e 73 61 72 68 6f 6c 67 75 72 75 67 72 61 6d 2e 78 79 7a 2f 67 65 74 6c 6f 63 61 74 69 6f 6e 2e 70 68 70 } //01 00 
		$a_01_2 = {70 67 69 6e 73 61 72 68 6f 6c 67 75 72 75 67 72 61 6d 2e 78 79 7a 2f 67 65 74 73 6d 73 2e 70 68 70 } //01 00 
		$a_01_3 = {2e 78 79 7a 2f 67 65 74 63 61 6c 6c 2e 70 68 70 } //01 00 
		$a_01_4 = {2e 78 79 7a 2f 67 65 74 61 75 64 69 6f 2e 70 68 70 } //00 00 
	condition:
		any of ($a_*)
 
}