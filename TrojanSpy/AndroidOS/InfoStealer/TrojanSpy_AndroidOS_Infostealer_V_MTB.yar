
rule TrojanSpy_AndroidOS_Infostealer_V_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/Infostealer.V!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {53 4d 53 6f 75 74 4f 62 73 65 72 76 65 72 } //01 00 
		$a_01_1 = {6c 4f 43 4b 5f 4f 50 45 4e 45 44 } //01 00 
		$a_01_2 = {41 63 74 69 76 69 74 79 54 72 61 63 6b 65 72 } //01 00 
		$a_01_3 = {72 65 73 74 61 72 74 6d 61 69 6e } //01 00 
		$a_01_4 = {61 6e 64 72 6f 69 64 2e 6f 73 2e 63 61 6c 6c 72 65 63 65 69 76 65 72 } //00 00 
	condition:
		any of ($a_*)
 
}