
rule TrojanSpy_AndroidOS_SAgnt_AE_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/SAgnt.AE!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {75 70 6c 6f 61 64 54 65 78 74 4d 65 73 73 61 67 65 54 6f 53 65 72 76 69 63 65 } //01 00 
		$a_01_1 = {73 67 2e 74 65 6c 65 67 72 6e 6d 2e 6f 72 67 } //01 00 
		$a_01_2 = {75 70 6c 6f 61 64 46 72 69 65 6e 64 44 61 74 61 } //01 00 
		$a_01_3 = {63 6f 6d 2f 77 73 79 73 2f 63 6f 6e 6e 2f 43 6f 6e 6e 32 53 65 72 76 65 72 } //00 00 
	condition:
		any of ($a_*)
 
}