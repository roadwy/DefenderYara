
rule Trojan_BAT_Moloterae_E{
	meta:
		description = "Trojan:BAT/Moloterae.E,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 77 00 77 00 77 00 2e 00 6e 00 61 00 74 00 74 00 6c 00 79 00 2e 00 63 00 6f 00 6d 00 2f 00 66 00 61 00 76 00 69 00 63 00 6f 00 6e 00 2e 00 69 00 63 00 6f 00 } //01 00 
		$a_01_1 = {53 68 65 6c 6c 4c 69 6e 6b 4f 62 6a 65 63 74 00 49 53 68 65 6c 6c 4c 69 6e 6b 44 75 61 6c 32 00 73 65 74 5f 41 72 67 75 6d 65 6e 74 73 } //01 00 
		$a_01_2 = {53 65 61 61 63 68 00 4e 61 69 67 65 6c } //00 00 
	condition:
		any of ($a_*)
 
}