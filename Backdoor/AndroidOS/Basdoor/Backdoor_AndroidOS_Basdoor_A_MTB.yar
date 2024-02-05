
rule Backdoor_AndroidOS_Basdoor_A_MTB{
	meta:
		description = "Backdoor:AndroidOS/Basdoor.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 07 00 00 01 00 "
		
	strings :
		$a_00_0 = {2f 72 61 74 2e 70 68 70 } //01 00 
		$a_00_1 = {5f 73 65 6e 64 6c 61 72 67 65 73 6d 73 } //01 00 
		$a_00_2 = {7e 74 65 73 74 2e 74 65 73 74 } //01 00 
		$a_00_3 = {72 65 73 75 6c 74 3d 6f 6b 26 61 63 74 69 6f 6e 3d 6e 77 6d 65 73 73 61 67 65 26 61 6e 64 72 6f 69 64 69 64 3d } //01 00 
		$a_00_4 = {53 65 6e 64 53 69 6e 67 6c 65 4d 65 73 73 61 67 65 } //01 00 
		$a_00_5 = {67 65 74 64 65 76 69 63 65 66 75 6c 6c 69 6e 66 6f } //01 00 
		$a_00_6 = {68 69 64 65 69 63 6f 6e } //00 00 
		$a_00_7 = {5d 04 00 00 } //0c 10 
	condition:
		any of ($a_*)
 
}