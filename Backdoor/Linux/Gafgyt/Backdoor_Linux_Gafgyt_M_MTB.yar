
rule Backdoor_Linux_Gafgyt_M_MTB{
	meta:
		description = "Backdoor:Linux/Gafgyt.M!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {54 43 50 53 4c 41 4d } //01 00 
		$a_01_1 = {4c 4f 4c 4e 4f 47 54 46 4f } //01 00 
		$a_01_2 = {49 73 24 75 70 65 72 40 64 6d 69 6e } //01 00 
		$a_01_3 = {78 6d 68 64 69 70 63 } //00 00 
	condition:
		any of ($a_*)
 
}