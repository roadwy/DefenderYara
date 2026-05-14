
rule Trojan_Win64_SelfDel_MK_MTB{
	meta:
		description = "Trojan:Win64/SelfDel.MK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,41 00 41 00 07 00 00 "
		
	strings :
		$a_01_0 = {5b 2a 5d 20 53 74 61 72 74 69 6e 67 20 6d 61 6c 77 61 72 65 20 73 61 6d 70 6c 65 } //15 [*] Starting malware sample
		$a_01_1 = {5b 2a 5d 20 58 4f 52 20 64 65 63 72 79 70 74 69 6e 67 } //10 [*] XOR decrypting
		$a_01_2 = {5b 2a 5d 20 46 6f 75 6e 64 20 25 73 20 28 50 49 44 3a 20 25 64 29 2c 20 69 6e 6a 65 63 74 69 6e 67 } //15 [*] Found %s (PID: %d), injecting
		$a_01_3 = {5b 2a 5d 20 4c 6f 61 64 69 6e 67 20 66 69 6c 65 32 2e 62 69 6e } //5 [*] Loading file2.bin
		$a_01_4 = {5b 2a 5d 20 44 65 63 6f 64 69 6e 67 20 42 61 73 65 36 34 } //5 [*] Decoding Base64
		$a_01_5 = {5b 2a 5d 20 52 75 6e 6e 69 6e 67 20 66 72 6f 6d 20 6d 65 6d 6f 72 79 } //10 [*] Running from memory
		$a_01_6 = {5b 2a 5d 20 43 6c 65 61 6e 69 6e 67 20 75 70 20 61 6e 64 20 65 78 69 74 69 6e 67 } //5 [*] Cleaning up and exiting
	condition:
		((#a_01_0  & 1)*15+(#a_01_1  & 1)*10+(#a_01_2  & 1)*15+(#a_01_3  & 1)*5+(#a_01_4  & 1)*5+(#a_01_5  & 1)*10+(#a_01_6  & 1)*5) >=65
 
}