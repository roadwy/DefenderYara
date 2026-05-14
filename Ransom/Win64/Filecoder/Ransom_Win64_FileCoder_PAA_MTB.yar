
rule Ransom_Win64_FileCoder_PAA_MTB{
	meta:
		description = "Ransom:Win64/FileCoder.PAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 07 00 00 "
		
	strings :
		$a_81_0 = {6d 61 69 6e 2e 64 72 6f 70 4e 6f 74 65 } //2 main.dropNote
		$a_81_1 = {6d 61 69 6e 2e 65 78 66 69 6c 50 72 69 76 61 74 65 4b 65 79 2e 64 65 66 65 72 77 72 61 70 31 } //1 main.exfilPrivateKey.deferwrap1
		$a_81_2 = {6d 61 69 6e 2e 65 6e 63 72 79 70 74 41 45 53 4b 65 79 } //1 main.encryptAESKey
		$a_81_3 = {47 6f 20 62 75 69 6c 64 20 49 44 3a } //1 Go build ID:
		$a_81_4 = {66 69 6c 65 73 20 6f 6e 20 74 68 69 73 20 63 6f 6d 70 75 74 65 72 20 61 72 65 20 6c 6f 63 6b 65 64 20 77 69 74 68 20 73 74 72 6f 6e 67 20 65 6e 63 72 79 70 74 69 6f 6e 20 28 52 53 41 2d 34 30 39 36 20 2b 20 41 45 53 2d 32 35 36 29 2e } //2 files on this computer are locked with strong encryption (RSA-4096 + AES-256).
		$a_81_5 = {2d 20 50 61 79 6d 65 6e 74 20 77 69 6e 64 6f 77 3a 20 34 38 20 68 6f 75 72 73 20 61 74 20 24 31 30 30 2e 20 41 66 74 65 72 20 74 68 61 74 20 70 72 69 63 65 20 64 6f 75 62 6c 65 73 20 74 6f } //1 - Payment window: 48 hours at $100. After that price doubles to
		$a_81_6 = {2e 6c 6f 63 6b 65 64 } //2 .locked
	condition:
		((#a_81_0  & 1)*2+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*2+(#a_81_5  & 1)*1+(#a_81_6  & 1)*2) >=10
 
}