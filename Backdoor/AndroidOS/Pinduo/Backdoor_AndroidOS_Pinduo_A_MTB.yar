
rule Backdoor_AndroidOS_Pinduo_A_MTB{
	meta:
		description = "Backdoor:AndroidOS/Pinduo.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {2e 70 69 6e 64 75 6f 64 75 6f 2e 63 6f 6d 2f 61 70 69 2f 73 65 72 76 65 72 } //01 00 
		$a_01_1 = {72 65 67 69 73 74 41 63 74 69 6f 6e 73 } //01 00 
		$a_01_2 = {43 6d 74 5a 65 75 73 43 6f 6e 66 69 67 } //01 00 
		$a_01_3 = {53 63 72 65 65 6e 53 74 61 74 65 54 72 61 63 6b 65 72 } //00 00 
	condition:
		any of ($a_*)
 
}