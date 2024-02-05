
rule Backdoor_AndroidOS_SpamBot_A_xp{
	meta:
		description = "Backdoor:AndroidOS/SpamBot.A!xp,SIGNATURE_TYPE_DEXHSTR_EXT,03 00 03 00 03 00 00 02 00 "
		
	strings :
		$a_00_0 = {3a 2f 2f 31 39 32 2e 32 32 35 2e 32 32 36 2e 31 31 34 3a 38 30 38 30 2f 53 6d 73 57 65 62 2f 41 64 64 53 6d 73 } //01 00 
		$a_02_1 = {63 6f 6d 2f 90 02 15 4c 61 75 6e 63 68 65 72 24 57 65 61 6b 48 61 6e 64 6c 65 72 24 31 90 00 } //01 00 
		$a_00_2 = {4c 63 6f 6d 2f 73 71 75 61 72 65 75 70 2f 6f 6b 68 74 74 70 2f 69 6e 74 65 72 6e 61 6c 2f 44 69 73 6b 4c 72 75 43 61 63 68 65 24 53 6e 61 70 73 68 6f 74 } //00 00 
		$a_00_3 = {5d 04 00 } //00 6c 
	condition:
		any of ($a_*)
 
}