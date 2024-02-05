
rule Trojan_Linux_Kinsing_L{
	meta:
		description = "Trojan:Linux/Kinsing.L,SIGNATURE_TYPE_ELFHSTR_EXT,05 00 05 00 06 00 00 01 00 "
		
	strings :
		$a_00_0 = {67 6f 2d 72 65 73 74 79 } //01 00 
		$a_00_1 = {67 6f 70 73 75 74 69 6c 2f 63 70 75 } //01 00 
		$a_00_2 = {64 69 73 6b 76 } //02 00 
		$a_01_3 = {6d 61 69 6e 2e 67 65 74 4d 69 6e 65 72 50 69 64 } //02 00 
		$a_00_4 = {6d 61 69 6e 2e 6d 61 73 73 63 61 6e } //02 00 
		$a_00_5 = {6d 61 69 6e 2e 62 61 63 6b 63 6f 6e 6e 65 63 74 } //00 00 
	condition:
		any of ($a_*)
 
}