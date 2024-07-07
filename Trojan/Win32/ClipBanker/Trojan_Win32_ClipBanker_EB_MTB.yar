
rule Trojan_Win32_ClipBanker_EB_MTB{
	meta:
		description = "Trojan:Win32/ClipBanker.EB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_01_0 = {65 74 43 6c 69 70 62 6f 61 72 64 44 61 74 61 } //1 etClipboardData
		$a_01_1 = {72 65 61 74 65 4d 75 74 65 78 57 } //1 reateMutexW
		$a_01_2 = {62 00 63 00 31 00 71 00 } //1 bc1q
		$a_03_3 = {68 00 02 00 00 6a 40 ff 15 90 01 04 68 80 00 00 00 50 6a ff 89 04 37 8d 45 84 50 53 53 ff 15 90 00 } //2
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*2) >=5
 
}
rule Trojan_Win32_ClipBanker_EB_MTB_2{
	meta:
		description = "Trojan:Win32/ClipBanker.EB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_01_0 = {43 72 65 61 74 65 4d 75 74 65 78 41 } //1 CreateMutexA
		$a_01_1 = {44 4a 53 48 44 48 46 45 4b 46 44 4d 56 43 } //1 DJSHDHFEKFDMVC
		$a_01_2 = {47 65 74 43 6c 69 70 62 6f 61 72 64 44 61 74 61 } //1 GetClipboardData
		$a_01_3 = {45 6d 70 74 79 43 6c 69 70 62 6f 61 72 64 } //1 EmptyClipboard
		$a_01_4 = {4f 70 65 6e 43 6c 69 70 62 6f 61 72 64 } //1 OpenClipboard
		$a_01_5 = {53 65 74 43 6c 69 70 62 6f 61 72 64 44 61 74 61 } //1 SetClipboardData
		$a_01_6 = {43 6c 6f 73 65 43 6c 69 70 62 6f 61 72 64 } //1 CloseClipboard
		$a_01_7 = {6b 76 77 33 65 39 30 6e 37 61 34 6c 68 30 71 6b 70 6a 38 32 39 38 39 30 68 36 32 73 75 70 6d 7a 6e 79 61 63 36 74 } //1 kvw3e90n7a4lh0qkpj829890h62supmznyac6t
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=8
 
}