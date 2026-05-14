
rule Ransom_MSIL_Loki_MX_MTB{
	meta:
		description = "Ransom:MSIL/Loki.MX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {7e c6 00 00 04 28 a3 02 00 06 11 01 7e c9 00 00 04 28 ab 02 00 06 13 02 20 00 00 00 00 28 be 00 00 06 39 7d ff ff ff } //1
		$a_80_1 = {4c 6f 6b 69 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 } //Loki.Properties.Resources  1
	condition:
		((#a_00_0  & 1)*1+(#a_80_1  & 1)*1) >=2
 
}