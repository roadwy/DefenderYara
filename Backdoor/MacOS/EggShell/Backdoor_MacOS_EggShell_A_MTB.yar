
rule Backdoor_MacOS_EggShell_A_MTB{
	meta:
		description = "Backdoor:MacOS/EggShell.A!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_02_0 = {6b 69 6c 6c 61 6c 6c 20 90 02 08 3b 65 63 68 6f 20 27 25 40 27 20 7c 20 73 75 64 6f 20 2d 53 20 62 61 73 68 20 26 3e 20 2f 64 65 76 2f 74 63 70 2f 25 40 2f 25 64 20 30 3e 26 31 20 32 3e 2f 64 65 76 2f 6e 75 6c 6c 90 00 } //01 00 
		$a_00_1 = {66 75 63 6b 20 25 64 } //01 00  fuck %d
		$a_01_2 = {2f 74 6d 70 2f 2e 61 76 61 74 6d 70 } //01 00  /tmp/.avatmp
		$a_01_3 = {70 72 6f 62 6c 65 6d 73 20 67 65 74 74 69 6e 67 20 70 61 73 73 77 6f 72 64 } //00 00  problems getting password
		$a_00_4 = {5d 04 00 } //00 65 
	condition:
		any of ($a_*)
 
}