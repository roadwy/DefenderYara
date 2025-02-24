
rule Ransom_Win64_FileCoder_AMCW_MTB{
	meta:
		description = "Ransom:Win64/FileCoder.AMCW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 08 00 00 "
		
	strings :
		$a_80_0 = {41 6e 64 20 79 6f 75 20 6a 75 73 74 20 6e 65 65 64 20 72 75 6e 20 74 68 69 73 20 73 6f 66 74 77 61 72 65 20 6f 6e 20 65 61 63 68 20 63 6f 6d 70 75 74 65 72 20 74 68 61 74 20 65 6e 63 72 79 70 74 65 64 20 61 6e 64 20 61 6c 6c 20 61 66 66 65 63 74 65 64 20 66 69 6c 65 73 20 77 69 6c 6c 20 62 65 20 64 65 63 72 79 70 74 65 64 } //And you just need run this software on each computer that encrypted and all affected files will be decrypted  5
		$a_80_1 = {57 65 20 73 65 6e 64 20 79 6f 75 20 61 20 73 69 6d 70 6c 65 20 73 6f 66 74 77 61 72 65 20 77 69 74 68 20 70 72 69 76 61 74 65 20 4b 65 79 } //We send you a simple software with private Key  2
		$a_80_2 = {53 68 6f 72 74 20 76 69 64 65 6f 20 6f 66 20 68 6f 77 20 74 6f 20 44 65 63 72 79 70 74 } //Short video of how to Decrypt  2
		$a_80_3 = {57 68 61 74 20 61 72 65 20 74 68 65 20 67 75 61 72 61 6e 74 65 65 73 20 74 68 61 74 20 49 20 63 61 6e 20 64 65 63 72 79 70 74 20 6d 79 20 66 69 6c 65 73 20 61 66 74 65 72 20 70 61 79 69 6e 67 20 74 68 65 20 72 61 6e 73 6f 6d } //What are the guarantees that I can decrypt my files after paying the ransom  3
		$a_80_4 = {54 68 69 73 20 6d 65 61 6e 73 20 74 68 61 74 20 77 65 20 63 61 6e 20 64 65 63 72 79 70 74 20 61 6c 6c 20 79 6f 75 72 20 66 69 6c 65 73 20 61 66 74 65 72 20 70 61 79 69 6e 67 20 74 68 65 20 72 61 6e 73 6f 6d } //This means that we can decrypt all your files after paying the ransom  3
		$a_80_5 = {4e 45 54 20 53 54 4f 50 20 49 49 53 41 44 4d 49 4e } //NET STOP IISADMIN  2
		$a_80_6 = {6e 65 74 20 73 74 6f 70 20 6d 79 73 71 6c } //net stop mysql  2
		$a_80_7 = {74 61 73 6b 6b 69 6c 6c 20 2f 46 20 2f 49 4d } //taskkill /F /IM  1
	condition:
		((#a_80_0  & 1)*5+(#a_80_1  & 1)*2+(#a_80_2  & 1)*2+(#a_80_3  & 1)*3+(#a_80_4  & 1)*3+(#a_80_5  & 1)*2+(#a_80_6  & 1)*2+(#a_80_7  & 1)*1) >=20
 
}