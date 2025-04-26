
rule Ransom_Win64_WannaCrypt_PF_MTB{
	meta:
		description = "Ransom:Win64/WannaCrypt.PF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {6c 69 6d 69 74 65 63 69 2f 57 61 6e 6e 61 43 72 79 2f 72 61 77 2f 6d 61 69 6e 2f 57 61 6e 6e 61 43 72 79 2e 45 58 45 } //1 limiteci/WannaCry/raw/main/WannaCry.EXE
		$a_01_1 = {63 6d 64 20 2f 63 20 69 6d 61 67 65 2e 70 6e 67 } //1 cmd /c image.png
		$a_01_2 = {4b 65 79 6c 6f 67 67 65 72 } //1 Keylogger
		$a_01_3 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 } //1 URLDownloadToFileA
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}