
rule Ransom_Win32_FileCryptor_G_MTB{
	meta:
		description = "Ransom:Win32/FileCryptor.G!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_02_0 = {45 6e 63 6f 64 65 72 3a 20 25 73 [0-20] 25 73 2e 6c 6f 63 6b } //1
		$a_02_1 = {45 6e 63 6f 64 65 72 20 [0-20] 20 53 74 61 72 74 } //1
		$a_00_2 = {46 69 6e 64 46 69 72 73 74 46 69 6c 65 41 } //1 FindFirstFileA
		$a_02_3 = {44 6f 63 75 6d 65 6e 74 73 20 61 6e 64 20 53 65 74 74 69 6e 67 73 [0-30] 65 6d 70 74 79 2e 6c 6f 63 6b } //1
		$a_00_4 = {54 6f 75 63 68 4d 65 4e 6f 74 5f 2e 74 78 74 } //1 TouchMeNot_.txt
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1+(#a_00_2  & 1)*1+(#a_02_3  & 1)*1+(#a_00_4  & 1)*1) >=5
 
}