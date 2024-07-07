
rule Trojan_Win32_ClipBanker_AK_MTB{
	meta:
		description = "Trojan:Win32/ClipBanker.AK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_01_0 = {63 6d 64 20 2f 43 20 22 73 74 61 72 74 20 22 71 22 } //1 cmd /C "start "q"
		$a_01_1 = {6c 6f 63 61 6c 61 70 70 64 61 74 61 } //1 localappdata
		$a_01_2 = {57 61 6b 65 41 6c 6c 43 6f 6e 64 69 74 69 6f 6e 56 61 72 69 61 62 6c 65 } //1 WakeAllConditionVariable
		$a_01_3 = {47 65 74 43 6c 69 70 62 6f 61 72 64 44 61 74 61 } //1 GetClipboardData
		$a_01_4 = {47 65 74 43 6c 69 70 62 6f 61 72 64 53 65 71 75 65 6e 63 65 4e 75 6d 62 65 72 } //1 GetClipboardSequenceNumber
		$a_01_5 = {55 73 65 72 73 5c 41 77 61 72 } //1 Users\Awar
		$a_01_6 = {63 6c 69 70 70 65 72 2d 6d 61 69 6e 2d 61 6c 6c 2d 63 72 79 70 74 6f } //1 clipper-main-all-crypto
		$a_01_7 = {53 65 74 75 70 2e 70 64 62 } //1 Setup.pdb
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=8
 
}