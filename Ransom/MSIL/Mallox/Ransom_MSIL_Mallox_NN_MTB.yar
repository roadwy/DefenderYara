
rule Ransom_MSIL_Mallox_NN_MTB{
	meta:
		description = "Ransom:MSIL/Mallox.NN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {91 1b 62 2b 1f 7b ad 03 ?? ?? 2b 1b 7b ab 03 ?? ?? 17 58 91 61 ?? ?? ?? ?? ?? 2a 02 2b d4 02 2b d3 02 2b d7 02 2b de 02 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}