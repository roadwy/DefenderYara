
rule DDoS_Linux_WprBlightre_A_MTB{
	meta:
		description = "DDoS:Linux/WprBlightre.A!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_00_0 = {2e 00 00 00 42 00 00 00 69 00 00 00 42 00 00 00 69 00 00 00 00 00 00 00 2e 00 00 00 6f 00 00 00 75 00 00 00 74 00 } //01 00 
		$a_00_1 = {5b 21 5d 20 57 61 69 74 69 6e 67 20 46 6f 72 20 51 75 65 75 65 20 00 5b 2b 5d 20 52 6f 75 6e 64 20 25 64 0a 00 } //00 00 
	condition:
		any of ($a_*)
 
}