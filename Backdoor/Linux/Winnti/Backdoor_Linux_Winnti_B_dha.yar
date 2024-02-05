
rule Backdoor_Linux_Winnti_B_dha{
	meta:
		description = "Backdoor:Linux/Winnti.B!dha,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {67 65 74 5f 6f 75 72 5f 73 6f 63 6b 65 74 73 } //01 00 
		$a_00_1 = {69 73 5f 69 6e 76 69 73 69 62 6c 65 5f 77 69 74 68 5f 70 69 64 73 } //01 00 
		$a_00_2 = {2f 75 73 72 2f 62 69 6e 2f 6e 65 74 73 74 61 74 } //01 00 
		$a_00_3 = {73 6f 63 6b 65 74 3a 5b 25 64 5d } //00 00 
	condition:
		any of ($a_*)
 
}