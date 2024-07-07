
rule Trojan_Win32_ClipBanker_RPW_MTB{
	meta:
		description = "Trojan:Win32/ClipBanker.RPW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_81_0 = {32 33 2e 38 38 2e 31 32 35 2e 32 30 } //1 23.88.125.20
		$a_81_1 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //1 SOFTWARE\Microsoft\Windows\CurrentVersion\Run
		$a_81_2 = {42 69 62 69 46 75 6e } //1 BibiFun
		$a_81_3 = {4d 75 74 65 4b 79 } //1 MuteKy
		$a_81_4 = {43 72 65 61 74 65 4d 75 74 65 78 57 } //1 CreateMutexW
		$a_81_5 = {47 65 74 43 6c 69 70 62 6f 61 72 64 44 61 74 61 } //1 GetClipboardData
		$a_81_6 = {45 6d 70 74 79 43 6c 69 70 62 6f 61 72 64 } //1 EmptyClipboard
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1) >=7
 
}