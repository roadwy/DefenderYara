
rule Ransom_Win64_FileCoder_RHAD_MTB{
	meta:
		description = "Ransom:Win64/FileCoder.RHAD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 06 00 00 "
		
	strings :
		$a_03_0 = {50 45 00 00 64 86 0f ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 0b 02 03 00 00 ?? 24 00 00 ?? 03 00 00 00 00 00 ?? ?? 06 } //2
		$a_01_1 = {48 65 78 61 4c 6f 63 6b 65 72 } //3 HexaLocker
		$a_01_2 = {70 72 65 63 69 73 65 6c 79 20 66 72 6f 6d 20 5a 5a 41 52 54 33 58 58 } //2 precisely from ZZART3XX
		$a_01_3 = {63 68 61 63 68 61 32 30 } //1 chacha20
		$a_01_4 = {79 6f 75 72 20 69 6d 70 6f 72 74 61 6e 74 20 66 69 6c 65 73 20 68 61 76 65 20 62 65 65 6e 20 65 6e 63 72 79 70 74 65 64 20 61 6e 64 20 74 68 65 20 6f 6e 6c 79 20 77 61 79 20 74 6f 20 72 65 63 6f 76 65 72 20 74 68 65 6d 20 69 73 20 74 6f 20 70 75 72 63 68 61 73 65 20 74 68 65 20 64 65 63 72 79 70 74 69 6f 6e 20 6b 65 79 } //1 your important files have been encrypted and the only way to recover them is to purchase the decryption key
		$a_01_5 = {66 6f 6c 6c 6f 77 20 74 68 65 73 65 20 69 6e 73 74 72 75 63 74 69 6f 6e 73 20 61 6e 64 20 70 75 72 63 68 61 73 65 20 74 68 65 20 64 65 63 72 79 70 74 69 6f 6e 20 6b 65 79 20 74 6f 20 72 65 63 6f 76 65 72 20 79 6f 75 72 20 65 6e 63 72 79 70 74 65 64 20 66 69 6c 65 73 } //1 follow these instructions and purchase the decryption key to recover your encrypted files
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*3+(#a_01_2  & 1)*2+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=10
 
}