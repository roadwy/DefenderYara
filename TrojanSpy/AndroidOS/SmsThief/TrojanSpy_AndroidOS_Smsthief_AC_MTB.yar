
rule TrojanSpy_AndroidOS_Smsthief_AC_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/Smsthief.AC!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {73 6d 73 72 65 63 69 76 65 72 2e 67 34 63 74 73 6e 65 6f 67 7a 6d 66 37 6e 64 72 78 7a 6c 64 38 67 66 65 77 65 62 71 32 30 65 66 32 65 2e 6f 72 67 2f 72 65 63 69 76 65 2e 70 68 70 } //01 00 
		$a_01_1 = {73 65 6e 64 53 4d 53 } //01 00 
		$a_01_2 = {67 65 74 49 50 41 64 64 72 65 73 73 } //01 00 
		$a_01_3 = {67 65 74 44 6f 6d 61 69 6e 2e 70 68 70 3f 73 72 76 } //01 00 
		$a_01_4 = {6b 6f 72 6f 6e 61 70 61 79 2e 63 61 73 68 } //00 00 
	condition:
		any of ($a_*)
 
}