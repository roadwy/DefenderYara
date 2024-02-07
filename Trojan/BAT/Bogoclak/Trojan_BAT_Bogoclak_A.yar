
rule Trojan_BAT_Bogoclak_A{
	meta:
		description = "Trojan:BAT/Bogoclak.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {55 00 73 00 65 00 72 00 20 00 73 00 65 00 6e 00 64 00 20 00 79 00 6f 00 75 00 20 00 6d 00 65 00 73 00 73 00 61 00 67 00 65 00 20 00 3a 00 } //01 00  User send you message :
		$a_01_1 = {53 63 72 65 6e 6e 00 } //01 00 
		$a_01_2 = {62 75 66 66 43 72 69 74 65 72 79 } //01 00  buffCritery
		$a_01_3 = {43 68 65 72 65 7a 53 68 74 6f } //01 00  CherezShto
		$a_01_4 = {42 61 63 6b 64 6f 6f 72 3e 62 5f 5f } //00 00  Backdoor>b__
	condition:
		any of ($a_*)
 
}