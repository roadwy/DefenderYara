
rule Trojan_Linux_Loki_A{
	meta:
		description = "Trojan:Linux/Loki.A,SIGNATURE_TYPE_ELFHSTR_EXT,09 00 09 00 05 00 00 02 00 "
		
	strings :
		$a_00_0 = {2f 73 74 61 74 } //02 00 
		$a_00_1 = {2f 73 77 61 70 74 } //02 00 
		$a_00_2 = {2f 71 75 69 74 } //05 00 
		$a_00_3 = {72 65 71 75 65 73 74 65 64 20 61 20 70 72 6f 74 6f 63 6f 6c 20 73 77 61 70 } //05 00 
		$a_00_4 = {72 65 71 75 65 73 74 65 64 20 61 6e 20 61 6c 6c 20 6b 69 6c 6c } //00 00 
	condition:
		any of ($a_*)
 
}