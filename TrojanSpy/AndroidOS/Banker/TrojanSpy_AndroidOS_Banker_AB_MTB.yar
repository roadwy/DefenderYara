
rule TrojanSpy_AndroidOS_Banker_AB_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/Banker.AB!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_03_0 = {63 6f 6d 2f 61 70 70 2f 6d 61 6e 61 67 65 72 2f 90 02 20 4d 61 69 6e 41 63 74 69 76 69 74 79 90 00 } //01 00 
		$a_01_1 = {75 70 6c 6f 61 64 64 61 74 61 } //01 00 
		$a_01_2 = {67 65 74 52 75 6e 6e 69 6e 67 54 61 73 6b 73 } //01 00 
		$a_01_3 = {63 61 72 64 5f 6e 75 6d 62 65 72 } //01 00 
		$a_01_4 = {73 61 76 65 70 65 72 73 6f 6e 61 6c 64 65 74 61 69 6c 73 5f 73 74 65 70 66 69 72 73 74 } //00 00 
	condition:
		any of ($a_*)
 
}