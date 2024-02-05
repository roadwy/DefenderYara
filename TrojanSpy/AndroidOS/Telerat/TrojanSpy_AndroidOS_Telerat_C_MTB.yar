
rule TrojanSpy_AndroidOS_Telerat_C_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/Telerat.C!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {62 6f 74 72 61 74 } //01 00 
		$a_01_1 = {74 65 6c 65 72 61 74 32 2e 74 78 74 } //01 00 
		$a_01_2 = {5f 73 6d 73 69 6e 73 5f 6d 65 73 73 61 67 65 73 65 6e 74 } //01 00 
		$a_01_3 = {5f 62 6f 74 5f 74 6f 6b 65 6e } //01 00 
		$a_01_4 = {5f 75 70 6c 6f 61 64 5f 70 68 6f 74 6f } //01 00 
		$a_01_5 = {67 65 74 6c 61 73 74 73 6d 73 } //01 00 
		$a_01_6 = {5f 66 69 6e 64 61 6c 6c 63 6f 6e 74 61 63 74 73 } //00 00 
	condition:
		any of ($a_*)
 
}