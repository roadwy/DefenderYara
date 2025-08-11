
rule Trojan_Win32_FileCoder_NF_MTB{
	meta:
		description = "Trojan:Win32/FileCoder.NF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_01_0 = {4b 71 78 2b 76 4f 55 4c 36 35 42 } //2 Kqx+vOUL65B
		$a_01_1 = {4b 69 2d 6d 55 58 4b 34 53 } //2 Ki-mUXK4S
		$a_01_2 = {71 51 66 32 6b 4f 66 } //2 qQf2kOf
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2) >=6
 
}
rule Trojan_Win32_FileCoder_NF_MTB_2{
	meta:
		description = "Trojan:Win32/FileCoder.NF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {e9 c1 00 00 00 83 65 c0 00 c7 45 c4 0f 2c 42 00 a1 ?? ?? ?? ?? 8d 4d c0 33 c1 89 45 ?? 8b 45 18 89 45 ?? 8b 45 0c 89 } //5
		$a_01_1 = {65 6e 63 72 79 70 74 65 64 2d 6e 6f 74 2d 77 61 6c 6c 2e 65 78 65 } //1 encrypted-not-wall.exe
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}
rule Trojan_Win32_FileCoder_NF_MTB_3{
	meta:
		description = "Trojan:Win32/FileCoder.NF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_01_0 = {a1 8c 26 43 00 42 8a 44 10 ff 88 44 17 ff 8b 0d 88 26 43 00 8b 3d 90 26 43 00 3b d1 7c e2 a1 84 26 43 00 } //3
		$a_01_1 = {8b 3d 90 26 43 00 33 d2 f7 f1 8a 4c 37 ff 8a 04 17 88 0c 17 8b 0d 90 26 43 00 88 44 31 ff a1 84 26 43 00 8b 3d 14 26 43 00 8b c8 c1 e9 19 c1 e0 07 } //2
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*2) >=5
 
}
rule Trojan_Win32_FileCoder_NF_MTB_4{
	meta:
		description = "Trojan:Win32/FileCoder.NF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 05 00 00 "
		
	strings :
		$a_01_0 = {43 72 79 70 74 6f 77 61 6c 6c 2e 68 74 6d } //2 Cryptowall.htm
		$a_01_1 = {53 65 6e 64 20 24 36 30 30 20 77 6f 72 74 68 20 6f 66 20 42 69 74 63 6f 69 6e 20 74 6f 20 74 68 69 73 20 61 64 64 72 65 73 73 } //1 Send $600 worth of Bitcoin to this address
		$a_01_2 = {44 65 63 72 79 70 74 69 6e 67 2e 2e 2e 20 44 4f 20 4e 4f 54 20 43 4c 4f 53 45 20 54 48 45 20 50 52 4f 47 52 41 4d } //1 Decrypting... DO NOT CLOSE THE PROGRAM
		$a_01_3 = {54 6f 20 67 65 74 20 74 68 65 20 6b 65 79 20 74 6f 20 64 65 63 72 79 70 74 20 66 69 6c 65 73 2c 20 79 6f 75 20 68 61 76 65 20 74 6f 20 70 61 69 64 } //1 To get the key to decrypt files, you have to paid
		$a_01_4 = {4f 75 72 20 64 65 6d 6f 63 72 61 63 79 20 61 73 20 62 65 65 6e 20 68 61 63 6b 65 64 } //1 Our democracy as been hacked
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=6
 
}
rule Trojan_Win32_FileCoder_NF_MTB_5{
	meta:
		description = "Trojan:Win32/FileCoder.NF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 07 00 00 "
		
	strings :
		$a_01_0 = {6e 65 62 65 7a 70 65 63 6e 79 77 65 62 2e 65 75 2f 63 6d 46 75 63 32 39 74 64 32 46 79 5a 51 2f 64 65 74 61 69 6c 2e 70 68 70 } //2 nebezpecnyweb.eu/cmFuc29td2FyZQ/detail.php
		$a_01_1 = {68 69 6a 61 63 6b 65 64 } //1 hijacked
		$a_01_2 = {52 45 47 20 41 44 44 20 48 4b 43 55 5c 53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e 20 2f 56 20 53 79 73 } //1 REG ADD HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run /V Sys
		$a_01_3 = {72 61 6e 73 6f 6d 77 61 72 65 } //1 ransomware
		$a_01_4 = {44 65 6c 65 74 65 46 69 6c 65 73 } //1 DeleteFiles
		$a_01_5 = {47 65 74 45 6e 63 72 79 70 74 65 64 46 69 6c 65 73 } //1 GetEncryptedFiles
		$a_01_6 = {64 65 63 72 79 70 74 69 6e 67 20 6d 65 73 73 61 67 65 } //1 decrypting message
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=8
 
}