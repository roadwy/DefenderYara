
rule Ransom_Win64_EpsilonRed_A{
	meta:
		description = "Ransom:Win64/EpsilonRed.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {46 69 6c 65 73 57 69 74 68 45 78 74 65 6e 73 69 6f 6e 73 2e 66 75 6e 63 31 } //1 FilesWithExtensions.func1
		$a_01_1 = {6d 61 69 6e 2e 6d 79 46 69 6c 65 57 } //1 main.myFileW
		$a_01_2 = {6d 61 69 6e 2e 65 50 4c } //1 main.ePL
		$a_01_3 = {63 72 79 70 74 6f 2f 61 65 73 2e 65 78 70 61 6e 64 4b 65 79 47 6f } //1 crypto/aes.expandKeyGo
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}