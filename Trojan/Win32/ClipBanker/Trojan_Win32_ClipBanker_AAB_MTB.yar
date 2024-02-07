
rule Trojan_Win32_ClipBanker_AAB_MTB{
	meta:
		description = "Trojan:Win32/ClipBanker.AAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 0a 00 00 01 00 "
		
	strings :
		$a_01_0 = {43 72 65 61 74 65 4d 75 74 65 78 41 } //01 00  CreateMutexA
		$a_01_1 = {71 6f 70 65 72 69 62 39 66 64 68 } //01 00  qoperib9fdh
		$a_01_2 = {35 59 77 70 61 5a 6a 34 48 70 48 53 45 70 53 46 78 57 37 41 66 51 52 35 74 75 6b 37 72 36 62 5a 61 } //01 00  5YwpaZj4HpHSEpSFxW7AfQR5tuk7r6bZa
		$a_01_3 = {47 6c 6f 62 61 6c 41 6c 6c 6f 63 } //01 00  GlobalAlloc
		$a_01_4 = {6c 73 74 72 63 70 79 6e 57 } //01 00  lstrcpynW
		$a_01_5 = {6c 73 74 72 63 61 74 41 } //01 00  lstrcatA
		$a_01_6 = {47 65 74 43 6c 69 70 62 6f 61 72 64 44 61 74 61 } //01 00  GetClipboardData
		$a_01_7 = {4f 70 65 6e 43 6c 69 70 62 6f 61 72 64 } //01 00  OpenClipboard
		$a_01_8 = {53 65 74 43 6c 69 70 62 6f 61 72 64 44 61 74 61 } //01 00  SetClipboardData
		$a_01_9 = {4d 75 6c 74 69 42 79 74 65 54 6f 57 69 64 65 43 68 61 72 } //00 00  MultiByteToWideChar
	condition:
		any of ($a_*)
 
}