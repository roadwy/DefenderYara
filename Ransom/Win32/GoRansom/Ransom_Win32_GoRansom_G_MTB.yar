
rule Ransom_Win32_GoRansom_G_MTB{
	meta:
		description = "Ransom:Win32/GoRansom.G!MTB,SIGNATURE_TYPE_PEHSTR,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {46 69 6c 65 73 20 68 61 76 65 20 62 65 65 6e 20 65 6e 63 72 79 70 74 65 64 20 62 79 20 54 68 65 20 47 6f 52 61 6e 73 6f 6d 20 50 4f 43 20 52 61 6e 73 6f 6d 77 61 72 65 } //1 Files have been encrypted by The GoRansom POC Ransomware
		$a_01_1 = {44 65 63 72 79 70 74 69 6f 6e 20 4b 65 79 20 69 73 20 68 61 72 64 63 6f 64 65 64 20 69 6e 20 74 68 65 20 62 69 6e 61 72 79 } //1 Decryption Key is hardcoded in the binary
		$a_01_2 = {55 73 65 73 20 58 4f 52 20 65 6e 63 72 79 70 74 69 6f 6e 20 77 69 74 68 20 61 6e 20 38 62 69 74 20 28 62 79 74 65 29 20 6b 65 79 } //1 Uses XOR encryption with an 8bit (byte) key
		$a_01_3 = {4f 6e 6c 79 20 32 35 35 20 70 6f 73 73 69 62 6c 65 20 6b 65 79 73 } //1 Only 255 possible keys
		$a_01_4 = {52 75 6e 20 74 68 65 20 72 61 6e 73 6f 6d 77 61 72 65 20 69 6e 20 74 68 65 20 63 6f 6d 6d 61 6e 64 20 6c 69 6e 65 20 77 69 74 68 20 6f 6e 65 20 61 72 67 75 6d 65 6e 74 2c 20 64 65 63 72 79 70 74 } //1 Run the ransomware in the command line with one argument, decrypt
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}