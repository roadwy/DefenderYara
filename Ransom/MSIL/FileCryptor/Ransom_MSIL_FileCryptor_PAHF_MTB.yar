
rule Ransom_MSIL_FileCryptor_PAHF_MTB{
	meta:
		description = "Ransom:MSIL/FileCryptor.PAHF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_00_0 = {2e 00 30 00 78 00 48 00 75 00 6e 00 74 00 65 00 72 00 } //1 .0xHunter
		$a_00_1 = {54 00 68 00 65 00 20 00 6b 00 65 00 79 00 20 00 69 00 73 00 20 00 63 00 6f 00 72 00 72 00 65 00 63 00 74 00 2c 00 20 00 59 00 6f 00 75 00 72 00 20 00 66 00 69 00 6c 00 65 00 73 00 20 00 68 00 61 00 76 00 65 00 20 00 62 00 65 00 65 00 6e 00 20 00 64 00 65 00 63 00 72 00 79 00 70 00 74 00 65 00 64 00 } //2 The key is correct, Your files have been decrypted
		$a_01_2 = {43 6c 73 45 6e 63 72 79 70 74 44 65 63 72 79 70 74 46 69 6c 65 73 } //1 ClsEncryptDecryptFiles
		$a_01_3 = {61 64 64 5f 53 68 75 74 64 6f 77 6e } //1 add_Shutdown
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=5
 
}