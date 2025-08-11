
rule Ransom_Win64_Sinobi_YAC_MTB{
	meta:
		description = "Ransom:Win64/Sinobi.YAC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 06 00 00 "
		
	strings :
		$a_01_0 = {2d 2d 65 6e 63 72 79 70 74 2d 6e 65 74 77 6f 72 6b } //1 --encrypt-network
		$a_01_1 = {2d 2d 6e 6f 2d 62 61 63 6b 67 72 6f 75 6e 64 } //1 --no-background
		$a_01_2 = {45 6e 63 72 79 70 74 20 6f 6e 6c 79 20 73 70 65 63 69 66 69 65 64 20 64 69 72 65 63 74 6f 72 79 } //1 Encrypt only specified directory
		$a_01_3 = {4c 6f 61 64 20 68 69 64 64 65 6e 20 64 72 69 76 65 73 20 } //1 Load hidden drives 
		$a_01_4 = {45 6e 63 72 79 70 74 69 6f 6e 20 6d 6f 64 65 } //1 Encryption mode
		$a_01_5 = {45 6e 61 62 6c 65 20 73 69 6c 65 6e 74 20 65 6e 63 72 79 70 74 69 6f 6e 20 28 6e 6f 20 65 78 74 65 6e 73 69 6f 6e 20 61 6e 64 20 6e 6f 74 65 73 20 77 69 6c 6c 20 62 65 20 61 64 64 65 64 29 } //10 Enable silent encryption (no extension and notes will be added)
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*10) >=15
 
}