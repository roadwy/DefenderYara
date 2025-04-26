
rule Ransom_MSIL_Makop_BK_MTB{
	meta:
		description = "Ransom:MSIL/Makop.BK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_01_0 = {59 03 8e 69 5d 91 59 20 fe 00 00 00 58 18 58 20 00 01 00 00 5d d2 9c 08 17 58 0c 08 6a 03 8e 69 17 59 6a 06 17 58 6e 5a 31 } //4
		$a_01_1 = {03 08 03 8e 69 5d 91 07 08 07 8e 69 5d } //1
	condition:
		((#a_01_0  & 1)*4+(#a_01_1  & 1)*1) >=5
 
}