
rule TrojanSpy_AndroidOS_Banker_D_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/Banker.D!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {4c 6f 72 67 2f 73 6c 65 6d 70 6f 2f 73 65 72 76 69 63 65 2f 61 63 74 69 76 69 74 69 65 73 2f 43 76 63 50 6f 70 75 70 3b } //01 00 
		$a_00_1 = {43 72 65 64 69 74 43 61 72 64 4e 75 6d 62 65 72 45 64 69 74 54 65 78 74 } //01 00 
		$a_00_2 = {69 6e 74 65 72 63 65 70 74 5f 73 6d 73 5f 73 74 61 72 74 } //01 00 
		$a_00_3 = {67 65 74 49 6e 73 74 61 6c 6c 65 64 41 70 70 73 4c 69 73 74 } //00 00 
		$a_00_4 = {5d 04 00 } //00 00 
	condition:
		any of ($a_*)
 
}