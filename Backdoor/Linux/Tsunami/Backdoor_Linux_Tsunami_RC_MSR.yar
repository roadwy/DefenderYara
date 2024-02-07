
rule Backdoor_Linux_Tsunami_RC_MSR{
	meta:
		description = "Backdoor:Linux/Tsunami.RC!MSR,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {77 67 65 74 20 90 02 05 3a 2f 2f 90 02 03 2e 90 02 03 2e 90 02 03 2e 90 02 03 2f 90 02 07 2f 90 02 07 2e 73 68 20 7c 7c 20 63 75 72 6c 20 2d 4f 20 90 02 05 3a 2f 2f 90 02 03 2e 90 02 03 2e 90 02 03 2e 90 02 03 2f 90 02 07 2f 90 02 07 2e 73 68 3b 20 62 75 73 79 62 6f 78 90 00 } //01 00 
		$a_01_1 = {4d 6f 6d 65 6e 74 75 6d 41 50 49 42 6f 74 } //00 00  MomentumAPIBot
	condition:
		any of ($a_*)
 
}