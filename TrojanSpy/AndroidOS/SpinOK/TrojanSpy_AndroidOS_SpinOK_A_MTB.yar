
rule TrojanSpy_AndroidOS_SpinOK_A_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/SpinOK.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {64 33 68 64 62 6a 74 62 31 36 38 36 74 6e 2e 63 6c 6f 75 64 66 72 6f 6e 74 2e 6e 65 74 } //01 00 
		$a_01_1 = {4c 63 6f 6d 2f 73 70 69 6e 2f 6f 6b 2f 67 70 2f 72 65 63 65 69 76 65 72 2f 53 70 69 6e 52 65 63 65 69 76 65 72 } //01 00 
		$a_01_2 = {2f 4f 6b 53 70 69 6e 50 72 6f 76 69 64 65 72 } //01 00 
		$a_01_3 = {2f 4f 6b 73 41 63 74 69 76 69 74 79 } //01 00 
		$a_01_4 = {41 45 53 2f 47 43 4d 2f 4e 6f 50 61 64 64 69 6e 67 } //00 00 
	condition:
		any of ($a_*)
 
}