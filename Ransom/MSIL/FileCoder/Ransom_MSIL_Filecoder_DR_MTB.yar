
rule Ransom_MSIL_Filecoder_DR_MTB{
	meta:
		description = "Ransom:MSIL/Filecoder.DR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_81_0 = {45 6e 63 72 79 70 74 46 69 6c 65 53 79 73 74 65 6d } //1 EncryptFileSystem
		$a_81_1 = {45 6e 63 72 79 70 74 69 6f 6e 4b 65 79 } //1 EncryptionKey
		$a_81_2 = {69 6e 73 74 61 6c 6c 5c 6f 62 6a 5c 52 65 6c 65 61 73 65 5c 69 6e 73 74 61 6c 6c 2e 70 64 62 } //1 install\obj\Release\install.pdb
		$a_81_3 = {55 73 65 72 73 5c 50 75 62 6c 69 63 5c 70 61 79 2e 6a 70 67 } //1 Users\Public\pay.jpg
		$a_81_4 = {2e 63 72 79 70 74 65 64 } //1 .crypted
		$a_81_5 = {49 76 61 6e 20 4d 65 64 76 65 64 65 76 } //1 Ivan Medvedev
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1) >=6
 
}