
rule Ransom_MSIL_Paradise_APA_MTB{
	meta:
		description = "Ransom:MSIL/Paradise.APA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {16 13 05 16 13 06 2b 37 1f 75 8d ?? ?? ?? 01 13 07 16 13 08 2b 15 11 07 11 08 08 11 05 91 9c 11 05 17 58 13 05 11 08 17 58 13 08 11 08 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}