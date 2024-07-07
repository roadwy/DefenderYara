
rule Ransom_MSIL_FileCryptor_D_MTB{
	meta:
		description = "Ransom:MSIL/FileCryptor.D!MTB,SIGNATURE_TYPE_PEHSTR,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {6c 6f 63 6b 65 72 } //1 locker
		$a_01_1 = {44 00 69 00 73 00 61 00 62 00 6c 00 65 00 54 00 61 00 73 00 6b 00 4d 00 67 00 72 00 } //1 DisableTaskMgr
		$a_01_2 = {6c 00 6f 00 6c 00 2e 00 65 00 6e 00 63 00 72 00 79 00 70 00 74 00 } //1 lol.encrypt
		$a_01_3 = {59 00 6f 00 75 00 72 00 20 00 66 00 69 00 6c 00 65 00 73 00 20 00 68 00 61 00 73 00 20 00 62 00 65 00 65 00 6e 00 20 00 65 00 6e 00 63 00 72 00 79 00 70 00 74 00 65 00 64 00 } //1 Your files has been encrypted
		$a_01_4 = {45 00 6e 00 63 00 72 00 79 00 70 00 74 00 65 00 64 00 46 00 69 00 6c 00 65 00 48 00 65 00 61 00 64 00 65 00 72 00 } //1 EncryptedFileHeader
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}