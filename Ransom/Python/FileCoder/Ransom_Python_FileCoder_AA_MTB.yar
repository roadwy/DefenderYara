
rule Ransom_Python_FileCoder_AA_MTB{
	meta:
		description = "Ransom:Python/FileCoder.AA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {62 65 73 74 6d 61 6c 77 61 72 65 [0-20] 70 79 69 2d 63 6f 6e 74 65 6e 74 73 2d 64 69 72 65 63 74 6f 72 79 } //1
		$a_01_1 = {65 6d 61 69 6c 2e 65 6e 63 6f 64 65 72 73 } //1 email.encoders
		$a_01_2 = {50 79 49 6e 73 74 61 6c 6c 65 72 3a 20 70 79 69 5f 77 69 6e 33 32 5f 75 74 69 6c 73 5f 74 6f 5f 75 74 66 38 } //1 PyInstaller: pyi_win32_utils_to_utf8
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}