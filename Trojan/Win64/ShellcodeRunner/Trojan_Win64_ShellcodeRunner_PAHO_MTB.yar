
rule Trojan_Win64_ShellcodeRunner_PAHO_MTB{
	meta:
		description = "Trojan:Win64/ShellcodeRunner.PAHO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 05 00 00 "
		
	strings :
		$a_01_0 = {42 43 72 79 70 74 44 65 63 72 79 70 74 5b 31 5d 20 46 61 69 6c 65 64 20 57 69 74 68 20 45 72 72 6f 72 3a 20 30 78 25 30 2e 38 58 } //1 BCryptDecrypt[1] Failed With Error: 0x%0.8X
		$a_01_1 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 45 78 20 66 61 69 6c 65 64 } //1 VirtualAllocEx failed
		$a_01_2 = {53 68 65 6c 6c 63 6f 64 65 20 73 69 7a 65 20 61 66 74 65 72 20 64 65 63 72 79 70 74 69 6f 6e } //5 Shellcode size after decryption
		$a_01_3 = {45 78 65 63 75 74 69 6e 67 20 73 68 65 6c 6c 63 6f 64 65 } //5 Executing shellcode
		$a_03_4 = {48 8b 45 10 48 89 45 e0 8b 45 18 89 45 e8 48 8b 45 20 48 89 45 f0 48 8b 45 28 48 89 45 f8 48 8d 45 d0 48 89 c1 e8 ?? ?? ?? ?? 85 c0 75 07 } //2
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*5+(#a_01_3  & 1)*5+(#a_03_4  & 1)*2) >=9
 
}