
rule Backdoor_iPhoneOS_EggShell_C_MTB{
	meta:
		description = "Backdoor:iPhoneOS/EggShell.C!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_00_0 = {2f 4c 69 62 72 61 72 79 2f 4c 61 75 6e 63 68 41 67 65 6e 74 73 2f 2e 65 73 70 6c 2e 70 6c 69 73 74 } //01 00 
		$a_00_1 = {5b 65 73 70 6c 20 6f 70 65 6e 41 70 70 3a 5d } //01 00 
		$a_00_2 = {2f 74 6d 70 2f 2e 61 76 61 74 6d 70 } //01 00 
		$a_00_3 = {67 65 74 46 75 6c 6c 43 4d 44 } //01 00 
		$a_00_4 = {74 61 6b 65 50 69 63 74 75 72 65 3a } //00 00 
		$a_00_5 = {5d 04 00 00 } //a0 08 
	condition:
		any of ($a_*)
 
}