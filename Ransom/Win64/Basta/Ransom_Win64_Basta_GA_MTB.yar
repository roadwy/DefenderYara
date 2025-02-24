
rule Ransom_Win64_Basta_GA_MTB{
	meta:
		description = "Ransom:Win64/Basta.GA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {03 c8 8b 05 30 7c 09 00 89 0d 4a 7c 09 00 48 8b 0d e7 7b 09 00 0f af 81 e8 00 00 00 89 05 16 7c 09 00 8b 81 d0 00 00 00 2b 46 74 2d 97 8f 48 01 31 41 4c 49 81 fa 38 f5 05 00 0f 8c } //1
		$a_01_1 = {56 69 73 69 62 6c 65 45 6e 74 72 79 } //1 VisibleEntry
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}