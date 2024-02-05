
rule TrojanSpy_AndroidOS_Imlog_A_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/Imlog.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {53 65 61 63 68 54 61 67 73 41 63 74 69 76 69 74 79 } //01 00 
		$a_01_1 = {47 4f 4f 47 4c 45 5f 41 44 5f 48 54 4d 4c } //01 00 
		$a_01_2 = {69 6d 6e 65 74 2e 75 73 2f 61 64 73 2f 65 77 61 6c 6c 70 61 70 65 72 73 5f 61 6c 6c 2e 68 74 6d 6c } //01 00 
		$a_01_3 = {49 53 53 59 4e 4f 4b } //00 00 
	condition:
		any of ($a_*)
 
}