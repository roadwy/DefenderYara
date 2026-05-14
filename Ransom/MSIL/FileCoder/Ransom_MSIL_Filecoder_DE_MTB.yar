
rule Ransom_MSIL_Filecoder_DE_MTB{
	meta:
		description = "Ransom:MSIL/Filecoder.DE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 06 00 00 "
		
	strings :
		$a_81_0 = {41 6c 6c 20 66 69 6c 65 73 20 69 6e 20 74 68 69 73 20 66 6f 6c 64 65 72 20 68 61 76 65 20 62 65 65 6e 20 65 6e 63 72 79 70 74 65 64 } //1 All files in this folder have been encrypted
		$a_03_1 = {70 00 6c 00 65 00 61 00 73 00 65 00 20 00 70 00 61 00 79 00 [0-0f] 42 00 54 00 43 00 } //1
		$a_03_2 = {70 6c 65 61 73 65 20 70 61 79 [0-0f] 42 54 43 } //1
		$a_81_3 = {67 65 74 20 79 6f 75 72 20 66 69 6c 65 73 20 62 61 63 6b } //1 get your files back
		$a_81_4 = {45 6e 63 72 79 70 74 65 64 20 66 69 6c 65 } //1 Encrypted file
		$a_81_5 = {2e 63 72 79 70 74 6f } //1 .crypto
	condition:
		((#a_81_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1) >=5
 
}