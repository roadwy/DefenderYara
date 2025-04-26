
rule Ransom_Win64_Cross_PA_MTB{
	meta:
		description = "Ransom:Win64/Cross.PA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,34 00 34 00 09 00 00 "
		
	strings :
		$a_01_0 = {63 75 72 72 65 6e 74 20 6d 61 63 68 69 6e 65 20 77 69 6c 6c 20 62 65 20 74 68 65 20 74 61 72 67 65 74 } //1 current machine will be the target
		$a_01_1 = {45 6e 63 72 79 70 74 20 74 68 65 20 73 70 65 63 69 66 69 65 64 20 70 61 74 68 } //1 Encrypt the specified path
		$a_01_2 = {44 4f 4e 27 54 20 52 45 4e 41 4d 45 2c 20 4f 52 20 54 52 59 20 54 4f 20 44 45 43 52 59 50 54 20 } //1 DON'T RENAME, OR TRY TO DECRYPT 
		$a_01_3 = {59 4f 55 20 57 49 4c 4c 20 4c 4f 53 45 20 41 4c 4c 20 59 4f 55 20 46 49 4c 45 53 20 41 4e 44 20 44 41 54 41 } //1 YOU WILL LOSE ALL YOU FILES AND DATA
		$a_01_4 = {59 6f 75 20 65 6e 74 69 72 65 20 6e 65 74 77 6f 72 6b 20 68 61 73 20 62 65 65 6e 20 63 6f 6d 70 72 6f 6d 69 73 65 64 } //10 You entire network has been compromised
		$a_01_5 = {65 6e 63 72 79 70 74 65 64 20 61 6e 64 20 79 6f 75 72 20 73 65 6e 73 69 74 69 76 65 20 64 61 74 61 20 } //10 encrypted and your sensitive data 
		$a_01_6 = {62 75 79 20 74 68 65 20 64 65 63 72 79 70 74 69 6f 6e 20 61 70 70 } //10 buy the decryption app
		$a_01_7 = {64 61 74 61 20 77 69 6c 6c 20 62 65 20 6c 65 61 6b 65 64 } //10 data will be leaked
		$a_01_8 = {47 6f 20 62 75 69 6c 64 20 49 44 3a } //10 Go build ID:
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*10+(#a_01_5  & 1)*10+(#a_01_6  & 1)*10+(#a_01_7  & 1)*10+(#a_01_8  & 1)*10) >=52
 
}