
rule TrojanSpy_AndroidOS_SAgnt_I_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/SAgnt.I!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_00_0 = {73 65 6e 64 53 4d 53 41 6c 6c } //01 00 
		$a_00_1 = {64 61 74 61 74 72 61 6e 73 66 65 72 2f 64 61 74 61 73 6e 61 70 73 68 6f 74 } //01 00 
		$a_00_2 = {73 65 6e 64 43 6f 6e 74 61 63 74 73 } //01 00 
		$a_00_3 = {73 75 62 6d 69 74 44 61 74 61 42 79 44 6f 50 6f 73 74 } //01 00 
		$a_00_4 = {73 65 6e 64 53 65 6e 74 } //01 00 
		$a_00_5 = {64 65 6c 65 74 65 73 6d 73 } //00 00 
	condition:
		any of ($a_*)
 
}