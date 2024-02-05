
rule TrojanSpy_AndroidOS_Tebak_A_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/Tebak.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {73 65 6e 64 5f 70 68 6f 6e 6c 69 73 74 2e 70 68 70 } //01 00 
		$a_01_1 = {73 65 6e 64 5f 73 69 6d 5f 6e 6f 2e 70 68 70 } //01 00 
		$a_01_2 = {70 72 69 6e 74 42 61 6e 6b 49 6e 66 6f 3d } //01 00 
		$a_01_3 = {73 65 6e 64 5f 62 61 6e 6b 2e 70 68 70 } //01 00 
		$a_01_4 = {62 61 6e 6b 20 6d 6f 62 69 6c 65 } //01 00 
		$a_01_5 = {74 74 70 3a 2f 2f 4d 2e 55 50 4c 4f 55 53 2e 4e 45 54 2f } //01 00 
		$a_00_6 = {4c 63 6f 6d 2f 65 72 69 63 2f 74 6e 74 32 } //00 00 
	condition:
		any of ($a_*)
 
}