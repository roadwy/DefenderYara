
rule Backdoor_Linux_NukeSped_A_MTB{
	meta:
		description = "Backdoor:Linux/NukeSped.A!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {77 61 69 74 70 69 64 } //01 00 
		$a_00_1 = {77 65 62 69 64 65 6e 74 5f 66 } //01 00 
		$a_00_2 = {66 75 64 63 69 74 79 64 65 6c 69 76 65 72 73 2e 63 6f 6d 2f 6e 65 74 2e 70 68 70 } //01 00 
		$a_00_3 = {73 63 74 65 6d 61 72 6b 65 74 73 2e 63 6f 6d 2f 6e 65 74 2e 70 68 70 } //00 00 
	condition:
		any of ($a_*)
 
}