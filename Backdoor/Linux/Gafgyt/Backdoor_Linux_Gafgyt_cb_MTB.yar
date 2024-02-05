
rule Backdoor_Linux_Gafgyt_cb_MTB{
	meta:
		description = "Backdoor:Linux/Gafgyt.cb!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {68 74 74 70 73 61 74 74 61 63 6b } //01 00 
		$a_00_1 = {63 75 72 6c 5f 77 67 65 74 5f 61 74 74 61 63 6b } //01 00 
		$a_00_2 = {42 4f 54 20 4a 4f 49 4e 45 44 } //01 00 
		$a_00_3 = {6b 69 6c 6c 65 72 5f 6b 69 6c 6c 5f 62 79 5f 70 6f 72 74 } //00 00 
	condition:
		any of ($a_*)
 
}