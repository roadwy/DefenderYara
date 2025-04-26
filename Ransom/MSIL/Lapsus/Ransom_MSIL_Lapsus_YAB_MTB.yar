
rule Ransom_MSIL_Lapsus_YAB_MTB{
	meta:
		description = "Ransom:MSIL/Lapsus.YAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {4c 61 70 73 75 73 5f 5f 52 61 6e 73 6f 6d } //1 Lapsus__Ransom
		$a_01_1 = {45 6e 63 72 79 70 74 44 69 72 65 63 74 6f 72 79 } //1 EncryptDirectory
		$a_01_2 = {02 28 4a 00 00 0a 0d 02 28 4b 00 00 0a 02 28 4c 00 00 0a 72 e6 08 00 70 28 0f 00 00 0a 28 4d 00 00 0a 13 04 11 04 08 28 4e 00 00 0a 00 02 28 4f 00 00 0a 00 11 04 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}