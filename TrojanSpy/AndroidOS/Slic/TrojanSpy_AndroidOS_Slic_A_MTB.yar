
rule TrojanSpy_AndroidOS_Slic_A_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/Slic.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {6c 6f 61 64 5f 73 6d 73 2e 70 68 70 } //01 00 
		$a_01_1 = {63 61 72 64 73 5f 6a 73 6f 6e 2e 70 68 70 } //01 00 
		$a_01_2 = {2f 64 65 76 2f 63 70 75 63 74 6c 2f 74 61 73 6b 73 } //01 00 
		$a_01_3 = {77 69 70 65 44 61 74 61 } //01 00 
		$a_01_4 = {73 65 69 43 75 6a 79 67 2f 76 42 2f 69 75 68 6c 79 73 75 69 } //00 00 
	condition:
		any of ($a_*)
 
}