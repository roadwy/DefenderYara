
rule Ransom_MSIL_FileCryptor_AYC_MTB{
	meta:
		description = "Ransom:MSIL/FileCryptor.AYC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 05 00 00 "
		
	strings :
		$a_01_0 = {59 6f 75 72 20 66 69 6c 65 73 20 68 61 76 65 20 62 65 65 6e 20 65 6e 63 72 79 70 74 65 64 } //5 Your files have been encrypted
		$a_01_1 = {63 6d 64 20 2f 63 20 76 73 73 61 64 6d 69 6e 2e 65 78 65 20 64 65 6c 65 74 65 20 73 68 61 64 6f 77 73 20 2f 61 6c 6c 20 2f 71 75 69 65 74 } //2 cmd /c vssadmin.exe delete shadows /all /quiet
		$a_00_2 = {5c 00 48 00 45 00 4c 00 50 00 2d 00 44 00 45 00 43 00 2e 00 74 00 78 00 74 00 } //1 \HELP-DEC.txt
		$a_00_3 = {2e 00 44 00 61 00 72 00 6b 00 6e 00 65 00 73 00 73 00 } //1 .Darkness
		$a_01_4 = {54 6f 20 65 6e 73 75 72 65 20 64 65 63 72 79 70 74 69 6f 6e 20 79 6f 75 20 63 61 6e 20 73 65 6e 64 20 31 2d 32 20 66 69 6c 65 73 20 28 6c 65 73 73 20 74 68 61 6e 20 31 4d 42 29 20 77 65 20 77 69 6c 6c 20 64 65 63 72 79 70 74 20 69 74 20 66 6f 72 20 66 72 65 65 2e } //1 To ensure decryption you can send 1-2 files (less than 1MB) we will decrypt it for free.
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*2+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_01_4  & 1)*1) >=10
 
}