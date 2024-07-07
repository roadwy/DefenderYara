
rule Ransom_MSIL_Ryzerlo_ARZ_MTB{
	meta:
		description = "Ransom:MSIL/Ryzerlo.ARZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {a2 0a 03 28 90 01 03 0a 0b 03 28 90 01 03 0a 0c 16 0d 2b 22 07 09 9a 28 90 01 03 0a 13 04 06 11 04 28 90 01 03 2b 2c 0a 02 07 09 9a 04 28 90 01 03 06 09 17 58 0d 09 07 8e 69 32 d8 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}