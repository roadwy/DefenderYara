
rule Backdoor_iPhoneOS_EggShell_D_MTB{
	meta:
		description = "Backdoor:iPhoneOS/EggShell.D!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,05 00 05 00 05 00 00 02 00 "
		
	strings :
		$a_00_0 = {45 67 67 53 68 65 6c 6c 2f 73 6f 75 72 63 65 2d 65 73 70 6c 6f 73 78 2f 65 73 70 6c 6f 73 78 2f 65 73 70 6c 2e 68 } //01 00 
		$a_00_1 = {2f 74 6d 70 2f 2e 61 76 61 74 6d 70 } //01 00 
		$a_00_2 = {65 73 70 6c 20 64 64 6f 73 3a } //01 00 
		$a_00_3 = {64 65 63 72 79 70 74 20 66 69 6c 65 2e 61 65 73 20 70 61 73 73 77 6f 72 64 31 32 33 34 } //01 00 
		$a_00_4 = {67 65 74 63 61 70 74 75 72 65 64 65 76 69 63 65 } //00 00 
		$a_00_5 = {5d 04 00 } //00 87 
	condition:
		any of ($a_*)
 
}