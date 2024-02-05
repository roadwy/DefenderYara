
rule Trojan_BAT_QuasarRAT_E_MTB{
	meta:
		description = "Trojan:BAT/QuasarRAT.E!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 05 00 00 02 00 "
		
	strings :
		$a_01_0 = {43 6c 69 65 6e 74 2e 54 65 73 74 73 } //02 00 
		$a_01_1 = {65 73 65 72 2e 43 6c 69 65 6e 74 2e 50 72 6f 70 65 72 74 69 65 73 } //01 00 
		$a_01_2 = {73 65 74 5f 57 69 6e 64 6f 77 53 74 79 6c 65 } //01 00 
		$a_01_3 = {73 65 74 5f 55 73 65 53 68 65 6c 6c 45 78 65 63 75 74 65 } //02 00 
		$a_01_4 = {53 00 48 00 41 00 32 00 35 00 36 00 50 00 52 00 4e 00 47 00 } //00 00 
	condition:
		any of ($a_*)
 
}