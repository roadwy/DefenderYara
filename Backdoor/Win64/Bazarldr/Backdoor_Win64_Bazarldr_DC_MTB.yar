
rule Backdoor_Win64_Bazarldr_DC_MTB{
	meta:
		description = "Backdoor:Win64/Bazarldr.DC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,37 00 37 00 11 00 00 "
		
	strings :
		$a_81_0 = {5c 41 75 74 6f 43 42 5c 52 65 6c 65 61 73 65 5c 41 75 74 6f 43 42 2e 70 64 62 } //20 \AutoCB\Release\AutoCB.pdb
		$a_81_1 = {41 75 74 6f 43 42 20 4d 46 43 20 41 70 70 6c 69 63 61 74 69 6f 6e } //20 AutoCB MFC Application
		$a_81_2 = {49 73 43 6c 69 70 62 6f 61 72 64 46 6f 72 6d 61 74 41 76 61 69 6c 61 62 6c 65 } //1 IsClipboardFormatAvailable
		$a_81_3 = {47 65 74 54 65 6d 70 46 69 6c 65 4e 61 6d 65 41 } //1 GetTempFileNameA
		$a_81_4 = {4c 6f 63 6b 52 65 73 6f 75 72 63 65 } //1 LockResource
		$a_81_5 = {47 65 74 44 69 73 6b 46 72 65 65 53 70 61 63 65 41 } //1 GetDiskFreeSpaceA
		$a_81_6 = {43 6f 70 79 46 69 6c 65 41 } //1 CopyFileA
		$a_81_7 = {44 65 6c 65 74 65 46 69 6c 65 41 } //1 DeleteFileA
		$a_81_8 = {57 72 69 74 65 46 69 6c 65 } //1 WriteFile
		$a_81_9 = {4c 6f 63 6b 46 69 6c 65 } //1 LockFile
		$a_81_10 = {53 65 74 45 6e 64 4f 66 46 69 6c 65 } //1 SetEndOfFile
		$a_81_11 = {49 73 44 65 62 75 67 67 65 72 50 72 65 73 65 6e 74 } //1 IsDebuggerPresent
		$a_81_12 = {50 6f 73 74 4d 65 73 73 61 67 65 41 } //1 PostMessageA
		$a_81_13 = {53 65 74 43 61 70 74 75 72 65 } //1 SetCapture
		$a_81_14 = {4b 69 6c 6c 54 69 6d 65 72 } //1 KillTimer
		$a_81_15 = {43 72 79 70 74 45 6e 63 72 79 70 74 } //1 CryptEncrypt
		$a_81_16 = {47 65 74 44 65 73 6b 74 6f 70 57 69 6e 64 6f 77 } //1 GetDesktopWindow
	condition:
		((#a_81_0  & 1)*20+(#a_81_1  & 1)*20+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1+(#a_81_9  & 1)*1+(#a_81_10  & 1)*1+(#a_81_11  & 1)*1+(#a_81_12  & 1)*1+(#a_81_13  & 1)*1+(#a_81_14  & 1)*1+(#a_81_15  & 1)*1+(#a_81_16  & 1)*1) >=55
 
}