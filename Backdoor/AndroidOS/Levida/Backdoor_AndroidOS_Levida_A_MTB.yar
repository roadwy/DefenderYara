
rule Backdoor_AndroidOS_Levida_A_MTB{
	meta:
		description = "Backdoor:AndroidOS/Levida.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {42 61 63 6b 44 6f 6f 72 49 6e 66 6f } //01 00 
		$a_01_1 = {63 6f 6d 2e 73 6c 2e 62 61 63 6b 64 6f 6f 72 } //01 00 
		$a_01_2 = {73 6c 69 63 6b 75 72 6c } //01 00 
		$a_01_3 = {63 61 72 72 69 65 72 73 65 72 76 2f 75 70 6c 6f 61 64 5f 64 61 74 61 } //01 00 
		$a_01_4 = {67 65 74 46 61 6b 65 4a 53 4f 4e } //01 00 
		$a_01_5 = {67 65 74 42 61 63 6b 44 6f 6f 72 } //01 00 
		$a_01_6 = {67 65 74 54 69 6d 65 46 72 6f 6d 46 69 72 73 74 49 6e 73 74 61 6c 6c } //00 00 
	condition:
		any of ($a_*)
 
}