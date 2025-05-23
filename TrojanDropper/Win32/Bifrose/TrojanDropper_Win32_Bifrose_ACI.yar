
rule TrojanDropper_Win32_Bifrose_ACI{
	meta:
		description = "TrojanDropper:Win32/Bifrose.ACI,SIGNATURE_TYPE_PEHSTR_EXT,09 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {8b 4d ec 83 c4 10 68 dc 17 40 00 51 e8 4d 01 00 00 8b d0 8d 4d e0 ff d6 } //5
		$a_00_1 = {3c 00 66 00 34 00 73 00 68 00 62 00 34 00 6e 00 67 00 40 00 23 00 40 00 70 00 75 00 72 00 69 00 64 00 65 00 65 00 3e 00 } //1 <f4shb4ng@#@puridee>
		$a_00_2 = {52 00 43 00 34 00 50 00 61 00 73 00 73 00 77 00 6f 00 72 00 74 00 } //1 RC4Passwort
		$a_00_3 = {5c 00 44 00 65 00 63 00 72 00 79 00 70 00 74 00 65 00 64 00 2e 00 65 00 78 00 65 00 } //1 \Decrypted.exe
		$a_00_4 = {2e 00 65 00 78 00 65 00 } //1 .exe
		$a_00_5 = {2e 00 74 00 6d 00 70 00 } //1 .tmp
	condition:
		((#a_01_0  & 1)*5+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1) >=6
 
}
rule TrojanDropper_Win32_Bifrose_ACI_2{
	meta:
		description = "TrojanDropper:Win32/Bifrose.ACI,SIGNATURE_TYPE_PEHSTR_EXT,17 00 15 00 05 00 00 "
		
	strings :
		$a_01_0 = {72 27 00 00 70 28 21 00 00 0a 72 31 00 00 70 28 19 00 00 0a 18 73 22 00 00 0a 0d 07 6f 23 00 00 0a d4 8d 11 00 00 01 13 04 07 11 04 16 11 04 8e 69 6f 24 00 00 0a 26 09 11 04 16 11 04 8e 69 6f 25 00 00 0a 08 6f 26 00 00 0a 09 6f 27 00 00 0a 2a } //10
		$a_01_1 = {28 05 00 00 06 72 27 00 00 70 28 21 00 00 0a 72 47 00 00 70 28 19 00 00 0a 07 28 2b 00 00 0a 73 2c 00 00 0a } //10
		$a_00_2 = {5c 00 73 00 79 00 73 00 64 00 78 00 2e 00 65 00 78 00 65 00 } //1 \sysdx.exe
		$a_00_3 = {5c 00 76 00 6b 00 64 00 33 00 32 00 2e 00 65 00 78 00 65 00 } //1 \vkd32.exe
		$a_00_4 = {68 00 69 00 64 00 65 00 69 00 74 00 2e 00 65 00 78 00 65 00 } //1 hideit.exe
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=21
 
}