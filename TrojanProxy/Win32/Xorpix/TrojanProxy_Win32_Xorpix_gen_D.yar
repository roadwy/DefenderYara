
rule TrojanProxy_Win32_Xorpix_gen_D{
	meta:
		description = "TrojanProxy:Win32/Xorpix.gen!D,SIGNATURE_TYPE_PEHSTR_EXT,28 03 28 03 0f 00 00 "
		
	strings :
		$a_03_0 = {55 8b ec 56 57 53 8b 7d 08 [0-02] 8b 75 10 8b df 03 5d 0c 8a 06 eb ?? [0-02] 30 07 90 90 47 46 3b fb 74 0d 8a 06 84 c0 75 f1 8b 75 10 8a 06 eb ea 5b 5f 5e c9 c2 0c 00 } //100
		$a_01_1 = {e8 00 00 00 00 58 05 0c 00 00 00 50 e9 } //100
		$a_02_2 = {89 85 d8 fe ff ff [0-10] c6 85 de fe ff ff 68 [0-10] 8b 85 d8 fe ff ff [0-10] 83 c0 1e [0-10] 89 85 df fe ff ff [0-10] 66 c7 85 e3 fe ff ff ff 15 [0-10] 8b 85 d8 fe ff ff [0-10] 83 c0 16 [0-10] 89 85 e5 fe ff ff [0-10] c6 85 e9 fe ff ff 68 [0-10] c7 85 ea fe ff ff 00 00 00 00 [0-10] 66 c7 85 ee fe ff ff ff 15 [0-10] 8b 85 d8 fe ff ff [0-10] 83 c0 1a [0-10] 89 85 f0 fe ff ff } //100
		$a_01_3 = {64 65 73 6b 74 6f 70 2e 69 6e 69 } //300 desktop.ini
		$a_01_4 = {70 72 6f 63 31 00 } //300 牰捯1
		$a_00_5 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 45 78 70 6c 6f 72 65 72 5c 53 68 65 6c 6c 20 46 6f 6c 64 65 72 73 } //1 Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders
		$a_01_6 = {53 65 44 65 62 75 67 50 72 69 76 69 6c 65 67 65 } //1 SeDebugPrivilege
		$a_01_7 = {47 65 74 54 68 72 65 61 64 43 6f 6e 74 65 78 74 } //1 GetThreadContext
		$a_00_8 = {4f 70 65 6e 50 72 6f 63 65 73 73 } //1 OpenProcess
		$a_00_9 = {50 72 6f 63 65 73 73 33 32 46 69 72 73 74 } //1 Process32First
		$a_01_10 = {57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //1 WriteProcessMemory
		$a_01_11 = {43 72 65 61 74 65 54 6f 6f 6c 68 65 6c 70 33 32 53 6e 61 70 73 68 6f 74 } //1 CreateToolhelp32Snapshot
		$a_01_12 = {43 72 65 61 74 65 52 65 6d 6f 74 65 54 68 72 65 61 64 } //1 CreateRemoteThread
		$a_00_13 = {43 72 65 61 74 65 50 72 6f 63 65 73 73 41 } //1 CreateProcessA
		$a_00_14 = {4f 70 65 6e 53 43 4d 61 6e 61 67 65 72 41 } //1 OpenSCManagerA
	condition:
		((#a_03_0  & 1)*100+(#a_01_1  & 1)*100+(#a_02_2  & 1)*100+(#a_01_3  & 1)*300+(#a_01_4  & 1)*300+(#a_00_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_00_8  & 1)*1+(#a_00_9  & 1)*1+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1+(#a_01_12  & 1)*1+(#a_00_13  & 1)*1+(#a_00_14  & 1)*1) >=808
 
}