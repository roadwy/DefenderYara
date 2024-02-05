
rule Backdoor_AndroidOS_Coudw_A_MTB{
	meta:
		description = "Backdoor:AndroidOS/Coudw.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 04 00 00 02 00 "
		
	strings :
		$a_00_0 = {4c 63 6f 6d 2f 63 6c 6f 75 64 73 2f 73 65 72 76 65 72 2f 53 68 43 6d 64 } //01 00 
		$a_00_1 = {73 68 65 6c 6c 63 6d 64 } //01 00 
		$a_00_2 = {73 79 73 74 65 6d 2f 62 69 6e 2f 70 6d 20 69 6e 73 74 61 6c 6c 20 2d 72 } //01 00 
		$a_00_3 = {6d 6f 75 6e 74 20 2d 6f 20 72 65 6d 6f 75 6e 74 2c 72 77 20 2f 73 79 73 74 65 6d } //00 00 
		$a_00_4 = {5d 04 00 00 } //9a eb 
	condition:
		any of ($a_*)
 
}