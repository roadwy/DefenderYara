
rule Ransom_Linux_Crypnux_A{
	meta:
		description = "Ransom:Linux/Crypnux.A,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {2f 72 65 61 64 6d 65 2e 63 72 79 70 74 6f 00 } //01 00 
		$a_01_1 = {2f 69 6e 64 65 78 2e 63 72 79 70 74 6f 00 } //01 00 
		$a_01_2 = {62 65 64 74 6c 73 5f 70 6b 5f 65 6e 63 72 79 70 74 00 } //01 00 
		$a_01_3 = {74 61 72 74 20 65 6e 63 72 79 70 74 69 6e 67 2e 2e 2e 00 } //01 00 
		$a_01_4 = {52 45 41 44 4d 45 5f 46 4f 52 5f 44 45 43 52 59 50 54 2e 74 78 74 00 } //00 00 
	condition:
		any of ($a_*)
 
}