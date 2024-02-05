
rule Trojan_Linux_Bedevil_B_MTB{
	meta:
		description = "Trojan:Linux/Bedevil.B!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,03 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {63 68 6b 72 6f 6f 74 6b 69 74 } //01 00 
		$a_00_1 = {49 43 4d 50 20 62 61 63 6b 64 6f 6f 72 20 75 70 } //01 00 
		$a_00_2 = {2e 2f 62 64 76 70 72 65 70 } //01 00 
		$a_00_3 = {62 69 6e 2f 73 74 61 74 69 79 69 63 72 68 67 65 2f 68 69 64 65 5f 70 6f 72 74 73 } //00 00 
	condition:
		any of ($a_*)
 
}