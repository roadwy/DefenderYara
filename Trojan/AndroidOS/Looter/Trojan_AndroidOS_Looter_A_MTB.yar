
rule Trojan_AndroidOS_Looter_A_MTB{
	meta:
		description = "Trojan:AndroidOS/Looter.A!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {53 75 70 65 72 53 55 5f 6c 65 6e } //01 00 
		$a_00_1 = {73 68 65 6c 6c 5f 75 6e 72 6f 6f 74 } //01 00 
		$a_00_2 = {73 68 65 6c 6c 5f 6e 6f 73 79 73 77 72 69 74 65 } //01 00 
		$a_00_3 = {4a 61 76 61 5f 63 6f 6d 5f 61 6c 65 70 68 7a 61 69 6e 5f 66 72 61 6d 61 72 6f 6f 74 5f 46 72 61 6d 61 41 63 74 69 76 69 74 79 5f 4c 61 75 6e 63 68 } //00 00 
		$a_00_4 = {5d 04 } //00 00 
	condition:
		any of ($a_*)
 
}