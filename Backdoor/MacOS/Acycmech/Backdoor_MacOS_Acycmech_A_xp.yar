
rule Backdoor_MacOS_Acycmech_A_xp{
	meta:
		description = "Backdoor:MacOS/Acycmech.A!xp,SIGNATURE_TYPE_MACHOHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_00_0 = {2f 63 6f 6e 66 73 2f 62 6f 74 25 75 2e 63 6f 6e 66 } //01 00 
		$a_00_1 = {41 63 79 63 6d 65 63 68 20 42 6f 74 20 25 64 20 43 6f 6e 66 69 67 } //01 00 
		$a_00_2 = {77 77 77 2e 63 79 63 6f 6d 6d 2d 6c 61 6d 6d 33 72 7a 2e 62 30 78 2e 72 6f } //00 00 
		$a_00_3 = {5d 04 00 } //00 94 
	condition:
		any of ($a_*)
 
}