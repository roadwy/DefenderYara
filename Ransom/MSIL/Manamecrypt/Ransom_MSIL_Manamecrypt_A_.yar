
rule Ransom_MSIL_Manamecrypt_A_{
	meta:
		description = "Ransom:MSIL/Manamecrypt.A!!Manamecrypt.gen!A,SIGNATURE_TYPE_ARHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_00_0 = {46 00 6f 00 72 00 6d 00 61 00 74 00 20 00 6d 00 65 00 6e 00 75 00 20 00 61 00 62 00 6f 00 76 00 65 00 20 00 5e 00 5e 00 5e 00 5e 00 20 00 61 00 6e 00 64 00 20 00 63 00 6c 00 69 00 63 00 6b 00 20 00 57 00 6f 00 72 00 64 00 20 00 57 00 72 00 61 00 70 00 } //1 Format menu above ^^^^ and click Word Wrap
		$a_00_1 = {5c 00 72 00 61 00 6e 00 73 00 6f 00 6d 00 2e 00 6a 00 70 00 67 00 } //1 \ransom.jpg
		$a_00_2 = {5c 00 44 00 65 00 63 00 72 00 79 00 70 00 74 00 65 00 72 00 2e 00 65 00 78 00 65 00 } //1 \Decrypter.exe
		$a_00_3 = {2e 00 74 00 61 00 78 00 32 00 30 00 31 00 35 00 } //1 .tax2015
		$a_00_4 = {2e 00 6c 00 6f 00 63 00 6b 00 65 00 64 00 } //1 .locked
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=4
 
}