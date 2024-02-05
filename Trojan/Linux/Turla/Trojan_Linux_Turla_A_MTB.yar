
rule Trojan_Linux_Turla_A_MTB{
	meta:
		description = "Trojan:Linux/Turla.A!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {2f 74 6d 70 2f 2e 73 79 6e 63 2e 70 69 64 } //01 00 
		$a_00_1 = {2f 72 6f 6f 74 2f 2e 73 65 73 73 69 6f 6e } //01 00 
		$a_00_2 = {2f 72 6f 6f 74 2f 2e 68 73 70 65 72 66 64 61 74 61 } //01 00 
		$a_00_3 = {46 69 6c 65 20 61 6c 72 65 61 64 79 20 65 78 69 73 74 20 6f 6e 20 72 65 6d 6f 74 65 20 66 69 6c 65 73 79 73 74 65 6d } //00 00 
	condition:
		any of ($a_*)
 
}