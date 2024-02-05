
rule Backdoor_Linux_Powbot_A{
	meta:
		description = "Backdoor:Linux/Powbot.A,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_00_0 = {6b 69 6c 6c 00 75 64 70 00 73 79 6e 00 74 63 70 61 6d 70 00 64 69 6c 64 6f 73 00 68 74 74 70 00 6d 69 6e 65 6c 6f 72 69 73 00 } //01 00 
		$a_00_1 = {38 39 2e 32 33 38 2e 31 35 30 2e 31 35 34 00 56 79 70 6f 72 00 77 6f 70 62 6f 74 20 68 61 73 20 73 74 61 72 74 65 64 00 } //00 00 
	condition:
		any of ($a_*)
 
}