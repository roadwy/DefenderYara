
rule Ransom_Win32_WannaCrypt_bit{
	meta:
		description = "Ransom:Win32/WannaCrypt!bit,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {40 57 61 6e 61 44 65 63 72 79 70 74 6f 72 40 2e 65 78 65 } //1 @WanaDecryptor@.exe
		$a_01_1 = {79 6f 75 72 20 66 69 6c 65 73 20 68 61 76 65 20 62 65 65 6e 20 65 6e 63 72 79 70 74 65 64 } //1 your files have been encrypted
		$a_01_2 = {59 6f 75 72 20 66 69 6c 65 73 20 77 69 6c 6c 20 62 65 20 6c 6f 73 74 } //1 Your files will be lost
		$a_01_3 = {53 65 6e 64 20 24 33 30 30 20 77 6f 72 74 68 20 6f 66 20 62 69 74 63 6f 69 6e 20 74 6f 20 74 68 69 73 20 61 64 64 72 65 73 73 } //1 Send $300 worth of bitcoin to this address
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}