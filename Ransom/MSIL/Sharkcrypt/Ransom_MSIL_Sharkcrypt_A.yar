
rule Ransom_MSIL_Sharkcrypt_A{
	meta:
		description = "Ransom:MSIL/Sharkcrypt.A,SIGNATURE_TYPE_PEHSTR,05 00 05 00 05 00 00 02 00 "
		
	strings :
		$a_01_0 = {3c 65 6e 63 72 79 70 74 5f 64 69 72 65 63 74 6f 72 79 3e 62 5f 5f 30 } //02 00 
		$a_01_1 = {53 68 61 72 6b 2e 65 78 65 } //01 00 
		$a_01_2 = {64 65 66 61 75 6c 74 5f 70 72 69 63 65 } //01 00 
		$a_01_3 = {2e 00 6c 00 6f 00 63 00 6b 00 65 00 64 00 } //01 00 
		$a_01_4 = {44 00 65 00 63 00 72 00 79 00 70 00 74 00 6f 00 72 00 2e 00 65 00 78 00 65 00 } //00 00 
		$a_01_5 = {00 5d 04 } //00 00 
	condition:
		any of ($a_*)
 
}