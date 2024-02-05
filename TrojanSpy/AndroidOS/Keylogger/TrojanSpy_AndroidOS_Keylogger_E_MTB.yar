
rule TrojanSpy_AndroidOS_Keylogger_E_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/Keylogger.E!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,08 00 08 00 05 00 00 05 00 "
		
	strings :
		$a_01_0 = {4c 63 6f 6d 2f 65 78 61 6d 70 6c 65 2f 77 68 61 74 73 75 70 70 } //01 00 
		$a_01_1 = {4d 79 44 69 66 66 69 63 75 6c 74 50 61 73 73 77 } //01 00 
		$a_01_2 = {74 63 70 2e 6e 67 72 6f 6b 2e 69 6f } //01 00 
		$a_01_3 = {72 65 76 65 72 73 65 5f 74 63 70 } //01 00 
		$a_01_4 = {66 69 78 2e 64 61 74 } //00 00 
	condition:
		any of ($a_*)
 
}