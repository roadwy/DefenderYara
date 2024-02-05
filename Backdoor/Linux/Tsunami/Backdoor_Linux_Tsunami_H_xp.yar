
rule Backdoor_Linux_Tsunami_H_xp{
	meta:
		description = "Backdoor:Linux/Tsunami.H!xp,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 05 00 00 02 00 "
		
	strings :
		$a_01_0 = {73 70 6f 6f 66 73 6d } //01 00 
		$a_01_1 = {67 65 74 73 70 6f 6f 66 73 } //01 00 
		$a_01_2 = {6b 69 6c 6c 61 6c 6c } //01 00 
		$a_01_3 = {74 73 75 6e 61 6d 69 } //01 00 
		$a_01_4 = {6b 61 69 74 65 6e 2e 63 } //00 00 
		$a_00_5 = {5d 04 00 00 } //ab 12 
	condition:
		any of ($a_*)
 
}