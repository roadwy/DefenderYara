
rule Ransom_MSIL_Choas_GVB_MTB{
	meta:
		description = "Ransom:MSIL/Choas.GVB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {06 02 07 91 7e 27 00 00 04 07 7e 27 00 00 04 6f 17 00 00 0a 5d 6f 23 00 00 0a 61 d2 6f c9 00 00 0a 07 17 58 0b 07 02 8e 69 32 d5 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}