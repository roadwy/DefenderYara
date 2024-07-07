
rule Ransom_Win64_BastaLoader_KF_MTB{
	meta:
		description = "Ransom:Win64/BastaLoader.KF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {41 89 c8 11 89 90 01 04 2c 90 01 01 3c 90 01 01 85 65 90 01 01 be 90 01 04 c8 90 01 03 89 76 90 01 01 65 79 90 00 } //1
		$a_03_1 = {89 c8 3b 70 90 01 01 30 89 90 01 04 29 aa 90 01 04 89 c8 00 89 90 01 04 89 c0 05 90 01 04 0d 90 01 04 0d 90 01 04 0d 90 01 04 69 be 90 01 08 7b 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}