
rule Backdoor_iPhoneOS_EggShell_A_MTB{
	meta:
		description = "Backdoor:iPhoneOS/EggShell.A!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {65 67 67 73 68 65 6c 6c 50 72 6f } //01 00 
		$a_00_1 = {74 61 6b 65 4f 72 64 65 72 41 6e 64 52 65 70 6c 79 3a 77 69 74 68 55 73 65 72 49 6e 66 6f 3a } //01 00 
		$a_00_2 = {63 6f 6d 2e 73 79 73 73 65 72 76 65 72 } //01 00 
		$a_00_3 = {61 74 74 65 6d 70 74 55 6e 6c 6f 63 6b 57 69 74 68 50 61 73 73 63 6f 64 65 3a } //00 00 
		$a_00_4 = {5d 04 00 } //00 d4 
	condition:
		any of ($a_*)
 
}