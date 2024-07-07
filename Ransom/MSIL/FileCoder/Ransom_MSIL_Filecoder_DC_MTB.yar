
rule Ransom_MSIL_Filecoder_DC_MTB{
	meta:
		description = "Ransom:MSIL/Filecoder.DC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_81_0 = {2e 5f 5f 5f 5f 5f 54 42 54 54 5f 5f 5f 5f 5f } //1 ._____TBTT_____
		$a_81_1 = {65 6e 63 72 79 70 74 6f 72 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 } //1 encryptor.Properties.Resources
		$a_81_2 = {46 69 6c 65 43 72 79 70 74 } //1 FileCrypt
		$a_81_3 = {47 65 6e 43 55 53 54 4f 4d 41 45 53 4b 65 79 } //1 GenCUSTOMAESKey
		$a_81_4 = {65 6e 63 72 79 70 74 6f 72 2e 70 64 62 } //1 encryptor.pdb
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=5
 
}
rule Ransom_MSIL_Filecoder_DC_MTB_2{
	meta:
		description = "Ransom:MSIL/Filecoder.DC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_81_0 = {41 6c 6c 20 6f 66 20 79 6f 75 72 20 66 69 6c 65 73 20 61 72 65 20 64 65 63 72 79 70 74 65 64 } //1 All of your files are decrypted
		$a_81_1 = {59 6f 75 20 63 61 6e 6e 6f 74 20 64 65 63 72 79 70 74 20 6d 6f 72 65 20 66 69 6c 65 73 20 66 6f 72 20 66 72 65 65 } //1 You cannot decrypt more files for free
		$a_81_2 = {54 6f 20 64 65 63 72 79 70 74 20 6d 6f 72 65 2c 20 63 6f 6e 74 61 63 74 3a 20 70 72 6f 67 72 61 6d 69 6c 65 74 69 73 69 6d 31 40 67 6d 61 69 6c 2e 63 6f 6d } //1 To decrypt more, contact: programiletisim1@gmail.com
		$a_81_3 = {2e 7a 65 72 6f 6e 69 6e 65 } //1 .zeronine
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=3
 
}