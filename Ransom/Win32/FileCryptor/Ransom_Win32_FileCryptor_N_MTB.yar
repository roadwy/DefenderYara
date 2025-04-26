
rule Ransom_Win32_FileCryptor_N_MTB{
	meta:
		description = "Ransom:Win32/FileCryptor.N!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 06 00 00 "
		
	strings :
		$a_81_0 = {2f 63 20 64 65 6c 20 43 3a 2a 20 2f 73 20 2f 71 } //1 /c del C:* /s /q
		$a_81_1 = {59 6f 75 20 43 61 6e 27 74 20 64 65 63 72 79 70 74 } //1 You Can't decrypt
		$a_81_2 = {52 61 6e 73 6f 6d 6e 6f 74 65 } //1 Ransomnote
		$a_81_3 = {79 6f 75 72 20 66 69 6c 65 73 20 77 69 6c 6c 20 62 65 20 64 65 6c 65 74 65 64 20 66 6f 72 65 76 65 72 } //1 your files will be deleted forever
		$a_81_4 = {52 65 64 65 72 5f 6c 6f 63 6b } //1 Reder_lock
		$a_81_5 = {2f 63 20 74 61 73 6b 6b 69 6c 6c 20 2f 69 6d 20 65 78 70 6c 6f 72 65 72 2e 65 78 65 20 2f 66 } //1 /c taskkill /im explorer.exe /f
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1) >=5
 
}