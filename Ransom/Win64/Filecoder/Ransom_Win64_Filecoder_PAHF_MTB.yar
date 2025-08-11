
rule Ransom_Win64_Filecoder_PAHF_MTB{
	meta:
		description = "Ransom:Win64/Filecoder.PAHF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 04 00 00 "
		
	strings :
		$a_01_0 = {48 8b 8c 24 80 00 00 00 48 8b 49 30 48 8b 94 24 98 00 00 00 48 89 14 24 48 8b 54 24 68 48 89 54 24 08 48 8b 54 24 70 48 89 54 24 10 44 0f 11 7c 24 18 48 c7 44 24 28 00 00 00 00 48 8b 84 } //2
		$a_01_1 = {24 a0 00 00 00 48 8b 9c 24 b0 00 00 00 48 8b 7c 24 78 48 89 de 49 89 f8 49 89 f9 48 89 ca 48 89 f9 ff d2 48 89 84 24 a8 00 00 00 48 89 9c 24 88 00 00 00 48 89 8c 24 } //2
		$a_01_2 = {2e 65 6e 63 } //1 .enc
		$a_01_3 = {45 6e 63 72 79 70 74 69 6e 67 } //1 Encrypting
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=6
 
}