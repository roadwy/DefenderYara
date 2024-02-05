
rule TrojanSpy_AndroidOS_SAgnt_P_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/SAgnt.P!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {6f 70 65 6e 53 4d 53 } //01 00 
		$a_01_1 = {53 65 72 76 69 63 65 4e 6f 74 69 66 4f 76 65 72 6c 61 79 } //01 00 
		$a_01_2 = {6f 70 65 6e 4c 69 73 74 65 6e 65 72 } //01 00 
		$a_01_3 = {2f 6d 6f 63 2e 6f 6e 61 70 65 65 73 } //00 00 
	condition:
		any of ($a_*)
 
}