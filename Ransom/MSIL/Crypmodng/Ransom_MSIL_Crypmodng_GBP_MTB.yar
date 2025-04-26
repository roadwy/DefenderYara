
rule Ransom_MSIL_Crypmodng_GBP_MTB{
	meta:
		description = "Ransom:MSIL/Crypmodng.GBP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {11 04 11 05 09 11 05 09 8e 69 5d 91 07 11 05 91 61 d2 9c 11 05 17 58 13 05 11 05 07 8e 69 32 e0 } //10
	condition:
		((#a_01_0  & 1)*10) >=10
 
}