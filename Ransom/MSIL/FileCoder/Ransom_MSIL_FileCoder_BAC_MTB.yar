
rule Ransom_MSIL_FileCoder_BAC_MTB{
	meta:
		description = "Ransom:MSIL/FileCoder.BAC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_81_0 = {59 6f 75 72 20 66 69 6c 65 73 20 61 72 65 20 65 6e 63 72 79 70 74 65 64 2c 20 69 6e 63 6c 75 64 69 6e 67 20 64 6f 63 75 6d 65 6e 74 73 2c 20 70 68 6f 74 6f 73 2c 20 76 69 64 65 6f 73 2c 20 64 61 74 61 62 61 73 65 73 2c 20 61 6e 64 20 6f 74 68 65 72 20 66 69 6c 65 73 } //1 Your files are encrypted, including documents, photos, videos, databases, and other files
		$a_81_1 = {72 61 6e 73 6f 6d 77 61 72 65 2e 70 64 62 } //1 ransomware.pdb
		$a_81_2 = {49 6e 70 75 74 20 44 65 63 72 79 70 74 20 4b 65 79 } //1 Input Decrypt Key
		$a_81_3 = {43 68 65 63 6b 20 50 61 79 6d 65 6e 74 } //1 Check Payment
		$a_81_4 = {52 61 6e 73 6f 6d 77 61 72 65 } //1 Ransomware
		$a_81_5 = {2e 6c 6f 63 6b } //1 .lock
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1) >=6
 
}