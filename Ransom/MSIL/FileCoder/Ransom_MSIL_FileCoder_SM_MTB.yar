
rule Ransom_MSIL_FileCoder_SM_MTB{
	meta:
		description = "Ransom:MSIL/FileCoder.SM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {00 11 04 07 09 91 58 06 09 06 8e 69 5d 91 58 20 00 01 00 00 5d 13 04 07 09 11 04 28 0b 00 00 06 00 00 09 17 58 0d 09 20 00 01 00 00 fe 04 13 08 11 08 2d cc } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}