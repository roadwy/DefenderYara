
rule Ransom_MSIL_HiddenTear_RDA_MTB{
	meta:
		description = "Ransom:MSIL/HiddenTear.RDA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {0d 06 7e 01 00 00 04 09 7e 01 00 00 04 6f 3b 00 00 0a 5e 6f 3c 00 00 0a 6f 43 00 00 0a 26 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}