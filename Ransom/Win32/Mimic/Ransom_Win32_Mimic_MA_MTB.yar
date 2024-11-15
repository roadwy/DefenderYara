
rule Ransom_Win32_Mimic_MA_MTB{
	meta:
		description = "Ransom:Win32/Mimic.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 07 00 00 "
		
	strings :
		$a_03_0 = {33 c0 c7 45 e8 00 00 00 00 68 ?? ?? 5d 00 8d 4d d8 c7 45 ec 07 00 00 00 66 89 45 d8 e8 ?? ?? fd ff 8b 45 e8 8d 55 8c 83 7d bc 08 8d 4d a8 6a 00 0f 43 4d a8 52 6a 00 68 06 01 02 00 8d 1c 00 33 c0 38 05 ?? ?? 5e } //5
		$a_01_1 = {4d 00 49 00 4d 00 49 00 43 00 5f 00 4c 00 4f 00 47 00 2e 00 74 00 78 00 74 00 } //2 MIMIC_LOG.txt
		$a_01_2 = {44 6f 6e 74 44 65 63 6f 6d 70 69 6c 65 4d 65 50 6c 65 61 73 65 } //2 DontDecompileMePlease
		$a_01_3 = {44 00 65 00 6c 00 65 00 74 00 65 00 20 00 53 00 68 00 61 00 64 00 6f 00 77 00 20 00 43 00 6f 00 70 00 69 00 65 00 73 00 } //2 Delete Shadow Copies
		$a_01_4 = {53 00 45 00 4c 00 45 00 43 00 54 00 20 00 2a 00 20 00 46 00 52 00 4f 00 4d 00 20 00 57 00 69 00 6e 00 33 00 32 00 5f 00 53 00 68 00 61 00 64 00 6f 00 77 00 43 00 6f 00 70 00 79 00 } //2 SELECT * FROM Win32_ShadowCopy
		$a_01_5 = {53 00 4f 00 46 00 54 00 57 00 41 00 52 00 45 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 43 00 75 00 72 00 72 00 65 00 6e 00 74 00 56 00 65 00 72 00 73 00 69 00 6f 00 6e 00 5c 00 52 00 75 00 6e 00 } //2 SOFTWARE\Microsoft\Windows\CurrentVersion\Run
		$a_01_6 = {43 68 61 43 68 61 32 30 20 66 6f 72 20 78 38 36 2c 20 43 52 59 50 54 4f 47 41 4d 53 20 62 79 } //1 ChaCha20 for x86, CRYPTOGAMS by
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2+(#a_01_5  & 1)*2+(#a_01_6  & 1)*1) >=16
 
}
rule Ransom_Win32_Mimic_MA_MTB_2{
	meta:
		description = "Ransom:Win32/Mimic.MA!MTB,SIGNATURE_TYPE_PEHSTR,04 00 04 00 03 00 00 "
		
	strings :
		$a_01_0 = {53 65 6c 66 44 65 6c 65 74 65 } //1 SelfDelete
		$a_01_1 = {68 69 64 63 6f 6e } //1 hidcon
		$a_01_2 = {45 76 65 72 79 74 68 69 6e 67 36 34 2e 64 6c 6c } //2 Everything64.dll
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*2) >=4
 
}