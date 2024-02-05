
rule Backdoor_Linux_Gafgyt_J_MTB{
	meta:
		description = "Backdoor:Linux/Gafgyt.J!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,03 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {48 54 54 50 53 54 4f 4d 50 } //01 00 
		$a_01_1 = {4f 56 48 4b 49 4c 4c } //01 00 
		$a_01_2 = {43 46 42 59 50 41 53 53 } //01 00 
		$a_01_3 = {4e 46 4f 4b 49 4c 4c } //00 00 
	condition:
		any of ($a_*)
 
}