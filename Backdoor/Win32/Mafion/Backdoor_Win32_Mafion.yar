
rule Backdoor_Win32_Mafion{
	meta:
		description = "Backdoor:Win32/Mafion,SIGNATURE_TYPE_PEHSTR_EXT,2d 00 2c 00 0d 00 00 "
		
	strings :
		$a_00_0 = {48 61 63 6b 65 72 } //10 Hacker
		$a_00_1 = {6d 73 6e 6d 73 67 72 2e 65 78 65 } //10 msnmsgr.exe
		$a_00_2 = {5c 57 49 4e 44 4f 57 53 5c 73 79 73 74 65 6d 33 32 5c 64 72 69 76 65 72 73 5c 6b 72 6e 6c 33 32 2e 62 61 74 } //10 \WINDOWS\system32\drivers\krnl32.bat
		$a_00_3 = {64 65 6c 20 5c 57 49 4e 44 4f 57 53 5c 73 79 73 74 65 6d 33 32 5c 73 65 72 76 69 63 65 2e 65 78 65 } //10 del \WINDOWS\system32\service.exe
		$a_00_4 = {53 68 75 74 64 6f 77 6e 4d 53 4e } //1 ShutdownMSN
		$a_00_5 = {4b 69 6c 6c 50 72 6f 63 65 73 73 } //1 KillProcess
		$a_01_6 = {44 69 73 61 62 6c 65 54 61 73 6b 4d 67 72 } //1 DisableTaskMgr
		$a_00_7 = {4f 70 65 6e 43 44 } //1 OpenCD
		$a_00_8 = {43 6c 6f 73 65 43 44 } //1 CloseCD
		$a_00_9 = {73 65 74 20 43 44 41 75 64 69 6f 20 64 6f 6f 72 } //1 set CDAudio door
		$a_00_10 = {42 6c 6f 63 6b 49 6e 70 75 74 } //1 BlockInput
		$a_01_11 = {53 77 61 70 4d 6f 75 73 65 42 75 74 74 6f 6e } //1 SwapMouseButton
		$a_00_12 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 } //1 URLDownloadToFileA
	condition:
		((#a_00_0  & 1)*10+(#a_00_1  & 1)*10+(#a_00_2  & 1)*10+(#a_00_3  & 1)*10+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_01_6  & 1)*1+(#a_00_7  & 1)*1+(#a_00_8  & 1)*1+(#a_00_9  & 1)*1+(#a_00_10  & 1)*1+(#a_01_11  & 1)*1+(#a_00_12  & 1)*1) >=44
 
}