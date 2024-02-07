
rule Trojan_Win32_ClipBanker_CC_MTB{
	meta:
		description = "Trojan:Win32/ClipBanker.CC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1b 00 1b 00 09 00 00 03 00 "
		
	strings :
		$a_81_0 = {5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 53 74 61 72 74 20 4d 65 6e 75 5c 50 72 6f 67 72 61 6d 73 5c 53 74 61 72 74 55 70 } //03 00  \Microsoft\Windows\Start Menu\Programs\StartUp
		$a_81_1 = {42 49 4f 53 20 53 79 73 74 65 6d 2e 65 78 65 } //03 00  BIOS System.exe
		$a_81_2 = {43 72 65 61 74 65 4d 75 74 65 78 41 } //03 00  CreateMutexA
		$a_81_3 = {45 78 70 6c 6f 72 65 72 5f 53 65 72 76 65 72 } //03 00  Explorer_Server
		$a_81_4 = {47 65 74 41 73 79 6e 63 4b 65 79 53 74 61 74 65 } //03 00  GetAsyncKeyState
		$a_81_5 = {47 65 74 43 6c 69 70 62 6f 61 72 64 44 61 74 61 } //03 00  GetClipboardData
		$a_81_6 = {49 73 43 6c 69 70 62 6f 61 72 64 46 6f 72 6d 61 74 41 76 61 69 6c 61 62 6c 65 } //03 00  IsClipboardFormatAvailable
		$a_81_7 = {43 6f 75 6e 74 43 6c 69 70 62 6f 61 72 64 46 6f 72 6d 61 74 73 } //03 00  CountClipboardFormats
		$a_81_8 = {45 6d 70 74 79 43 6c 69 70 62 6f 61 72 64 } //00 00  EmptyClipboard
	condition:
		any of ($a_*)
 
}