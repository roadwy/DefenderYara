
rule Ransom_MSIL_Chimera_AR_MTB{
	meta:
		description = "Ransom:MSIL/Chimera.AR!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {06 07 02 07 91 03 07 91 61 d2 9c 07 17 58 0b 07 02 8e 69 32 eb } //1
		$a_01_1 = {02 17 9a 11 05 91 28 0f 00 00 06 61 09 02 18 9a 11 05 91 28 0f 00 00 06 61 11 04 02 19 9a 11 05 91 28 0f 00 00 06 61 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}