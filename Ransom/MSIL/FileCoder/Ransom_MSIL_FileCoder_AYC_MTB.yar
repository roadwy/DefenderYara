
rule Ransom_MSIL_FileCoder_AYC_MTB{
	meta:
		description = "Ransom:MSIL/FileCoder.AYC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 05 00 00 "
		
	strings :
		$a_01_0 = {48 00 41 00 43 00 4b 00 45 00 44 00 20 00 42 00 59 00 20 00 50 00 41 00 50 00 41 00 5a 00 } //2 HACKED BY PAPAZ
		$a_01_1 = {70 00 61 00 70 00 61 00 7a 00 32 00 32 00 40 00 70 00 72 00 6f 00 74 00 6f 00 6e 00 2e 00 6d 00 65 00 } //1 papaz22@proton.me
		$a_01_2 = {42 00 65 00 6e 00 69 00 6f 00 6b 00 75 00 2e 00 74 00 78 00 74 00 } //1 Benioku.txt
		$a_01_3 = {53 00 4f 00 46 00 54 00 57 00 41 00 52 00 45 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 43 00 75 00 72 00 72 00 65 00 6e 00 74 00 56 00 65 00 72 00 73 00 69 00 6f 00 6e 00 5c 00 52 00 75 00 6e 00 } //1 SOFTWARE\Microsoft\Windows\CurrentVersion\Run
		$a_01_4 = {43 72 65 61 74 65 45 6e 63 72 79 70 74 6f 72 } //1 CreateEncryptor
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=6
 
}