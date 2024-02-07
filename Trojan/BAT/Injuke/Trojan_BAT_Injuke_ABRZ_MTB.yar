
rule Trojan_BAT_Injuke_ABRZ_MTB{
	meta:
		description = "Trojan:BAT/Injuke.ABRZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 03 00 "
		
	strings :
		$a_01_0 = {53 6f 6d 65 62 6f 34 79 2e 39 69 6e 65 2e 72 65 73 6f 75 72 63 65 73 } //03 00  Somebo4y.9ine.resources
		$a_01_1 = {53 00 6f 00 6d 00 65 00 62 00 6f 00 34 00 79 00 2e 00 50 00 72 00 6f 00 70 00 65 00 72 00 74 00 69 00 65 00 73 00 2e 00 52 00 65 00 73 00 6f 00 75 00 72 00 63 00 65 00 73 } //01 00 
		$a_01_2 = {4c 00 61 00 67 00 72 00 61 00 6e 00 67 00 65 00 50 00 6f 00 6c 00 79 00 6e 00 6f 00 6d 00 69 00 61 00 6c 00 } //00 00  LagrangePolynomial
	condition:
		any of ($a_*)
 
}