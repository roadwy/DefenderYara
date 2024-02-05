
rule Trojan_Linux_SAgnt_C_MTB{
	meta:
		description = "Trojan:Linux/SAgnt.C!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,05 00 05 00 04 00 00 02 00 "
		
	strings :
		$a_01_0 = {6d 61 69 6e 2e 57 72 69 74 65 52 65 61 64 6d 65 } //02 00 
		$a_01_1 = {6d 61 69 6e 2e 43 68 61 6e 67 65 50 61 73 73 77 6f 72 64 } //01 00 
		$a_01_2 = {2f 72 6f 6f 74 2f 62 6f 74 2f 6d 61 69 6e 2e 67 6f } //01 00 
		$a_01_3 = {70 61 74 63 68 62 6f 74 } //00 00 
	condition:
		any of ($a_*)
 
}