
rule Ransom_Win64_Pe32Skip_YAC_MTB{
	meta:
		description = "Ransom:Win64/Pe32Skip.YAC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 07 00 00 "
		
	strings :
		$a_01_0 = {70 61 79 6d 65 6e 74 20 69 73 20 72 65 71 75 69 72 65 64 2e } //1 payment is required.
		$a_01_1 = {57 68 61 74 20 64 72 69 76 65 20 64 6f 20 79 6f 75 20 77 61 6e 74 20 74 6f 20 65 6e 63 72 79 70 74 } //1 What drive do you want to encrypt
		$a_01_2 = {66 69 6c 65 73 20 68 61 76 65 20 62 65 65 6e 20 65 6e 63 72 79 70 74 65 64 } //1 files have been encrypted
		$a_01_3 = {70 61 79 6d 65 6e 74 20 69 73 20 72 65 71 75 69 72 65 64 } //1 payment is required
		$a_01_4 = {50 6c 65 61 73 65 20 6e 6f 74 65 20 74 68 61 74 20 63 6f 73 74 20 66 6f 72 20 66 69 6c 65 20 64 65 63 72 79 70 74 69 6f 6e 20 61 6e 64 20 61 76 6f 69 64 69 6e 67 20 64 61 74 61 20 70 75 62 6c 69 66 69 63 61 74 69 6f 6e 20 69 73 20 73 65 70 61 72 61 74 65 2e } //1 Please note that cost for file decryption and avoiding data publification is separate.
		$a_01_5 = {64 65 63 72 79 70 74 69 6f 6e 20 74 65 73 74 } //1 decryption test
		$a_01_6 = {6c 6f 63 6b 2e 70 65 33 32 53 6b 69 70 } //10 lock.pe32Skip
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*10) >=16
 
}