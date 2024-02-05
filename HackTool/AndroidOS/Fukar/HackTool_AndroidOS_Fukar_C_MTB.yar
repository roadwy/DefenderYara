
rule HackTool_AndroidOS_Fukar_C_MTB{
	meta:
		description = "HackTool:AndroidOS/Fukar.C!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {63 6f 6d 2f 64 64 6f 73 2f 73 74 6f 70 77 61 72 } //01 00 
		$a_01_1 = {63 6f 6d 2e 64 64 6f 73 2e 43 79 62 65 72 41 7a 6f 76 } //01 00 
		$a_01_2 = {64 31 77 70 36 6d 35 36 73 71 77 37 34 61 2e 63 6c 6f 75 64 66 72 6f 6e 74 2e 6e 65 74 2f 7e 61 73 73 65 74 73 2f } //01 00 
		$a_01_3 = {70 61 79 6c 6f 61 64 } //01 00 
		$a_01_4 = {6a 61 76 61 53 63 72 69 70 74 45 6e 61 62 6c 65 64 } //00 00 
	condition:
		any of ($a_*)
 
}