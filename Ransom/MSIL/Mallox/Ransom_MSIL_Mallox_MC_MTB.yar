
rule Ransom_MSIL_Mallox_MC_MTB{
	meta:
		description = "Ransom:MSIL/Mallox.MC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {03 09 03 6f 90 01 03 0a 09 59 6f 90 01 03 0a 13 0d 07 11 0d 02 7b 18 00 00 04 73 4c 00 00 0a 6f 90 01 03 0a 07 13 0e 11 0e 2a 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}