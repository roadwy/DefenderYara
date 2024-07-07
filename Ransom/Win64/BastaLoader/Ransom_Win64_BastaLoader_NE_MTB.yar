
rule Ransom_Win64_BastaLoader_NE_MTB{
	meta:
		description = "Ransom:Win64/BastaLoader.NE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {31 3a 3a 9c 59 90 01 04 44 ec 33 4f 90 01 01 43 43 eb 90 01 01 34 90 01 01 ac 1b 44 6c 90 01 01 c7 47 90 00 } //1
		$a_03_1 = {31 3a 3a 9c 59 90 01 04 ec d3 c7 42 63 43 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}