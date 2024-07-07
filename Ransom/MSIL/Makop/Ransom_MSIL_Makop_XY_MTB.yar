
rule Ransom_MSIL_Makop_XY_MTB{
	meta:
		description = "Ransom:MSIL/Makop.XY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {58 4a 03 8e 69 5d 03 06 1a 58 4a 03 8e 69 5d 91 07 06 1a 58 4a 07 8e 69 5d 91 61 28 2f 00 00 0a 03 06 1a 58 4a 1d 58 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}