
rule DDoS_Linux_SAgnt_B_MTB{
	meta:
		description = "DDoS:Linux/SAgnt.B!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {41 74 74 61 63 6b 57 6f 72 6b 65 72 } //01 00 
		$a_01_1 = {44 65 61 6c 77 69 74 68 44 44 6f 53 } //01 00 
		$a_01_2 = {64 6e 73 41 6d 70 } //01 00 
		$a_01_3 = {66 6c 6f 6f 64 2e 63 } //01 00 
		$a_01_4 = {75 64 70 5f 63 68 65 63 6b 73 75 6d } //00 00 
	condition:
		any of ($a_*)
 
}