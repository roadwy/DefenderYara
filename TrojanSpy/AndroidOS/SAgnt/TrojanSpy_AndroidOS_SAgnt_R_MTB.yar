
rule TrojanSpy_AndroidOS_SAgnt_R_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/SAgnt.R!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {75 70 6c 6f 61 64 44 65 76 69 63 65 49 6e 66 6f } //01 00 
		$a_01_1 = {6d 65 73 73 61 67 65 54 6f 41 6c 6c 43 6f 6e 74 61 63 74 73 } //01 00 
		$a_01_2 = {63 61 70 74 75 72 65 4d 69 63 72 6f 70 68 6f 6e 65 } //01 00 
		$a_01_3 = {63 61 70 74 75 72 65 43 61 6d 65 72 61 4d 61 69 6e } //01 00 
		$a_01_4 = {75 70 6c 6f 61 64 43 6f 6e 74 61 63 74 } //00 00 
	condition:
		any of ($a_*)
 
}