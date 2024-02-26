
rule Ransom_MSIL_Mallox_NN_MTB{
	meta:
		description = "Ransom:MSIL/Mallox.NN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_03_0 = {91 1b 62 2b 1f 7b ad 03 90 01 02 2b 1b 7b ab 03 90 01 02 17 58 91 61 90 01 05 2a 02 2b d4 02 2b d3 02 2b d7 02 2b de 02 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}