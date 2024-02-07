
rule TrojanDropper_Win32_SpamThru_gen_A{
	meta:
		description = "TrojanDropper:Win32/SpamThru.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,7d 00 7d 00 15 00 00 14 00 "
		
	strings :
		$a_02_0 = {2b cf 8d 04 c5 90 01 03 00 8b 50 04 85 d2 74 1e 8b 30 8d 3c 02 83 c0 08 3b c7 73 ed 0f b7 10 03 15 90 01 03 00 01 0c 32 03 d6 40 40 eb ea 90 00 } //14 00 
		$a_00_1 = {8b d6 8a 02 8d 72 01 88 07 47 84 c0 74 0b 49 74 0c 8a 06 88 07 47 46 eb f1 85 c9 75 0d 80 27 00 8a 06 46 84 c0 75 f9 } //14 00 
		$a_00_2 = {8a 0e 8d 46 01 88 0a 42 84 c9 74 0b 4f 74 0c 8a 08 88 0a 42 40 eb f1 85 ff 75 0a 80 22 00 8a 08 40 84 c9 75 f9 } //83 ff 
		$a_00_3 = {43 3a 5c 70 72 6f 6a 65 63 74 73 5c 41 6e 69 54 61 5c 33 32 } //83 ff  C:\projects\AniTa\32
		$a_80_4 = {77 65 62 65 78 } //webex  83 ff 
		$a_00_5 = {26 00 41 00 62 00 6f 00 75 00 74 00 20 00 4f 00 6c 00 6d 00 65 00 6b 00 2e 00 2e 00 2e 00 } //64 00  &About Olmek...
		$a_00_6 = {76 63 32 30 78 63 30 30 75 } //83 ff  vc20xc00u
		$a_00_7 = {44 3a 5c 53 72 63 5c 49 43 5c 4f 6c 6d 65 6b } //83 ff  D:\Src\IC\Olmek
		$a_01_8 = {42 00 41 00 4d 00 42 00 41 00 4c 00 41 00 4d 00 5f 00 47 00 45 00 54 00 49 00 4e 00 49 00 2e 00 50 00 48 00 50 00 } //83 ff  BAMBALAM_GETINI.PHP
		$a_00_9 = {50 69 63 6b 75 70 5f 4d 6f 65 67 6c 69 63 68 5f 4f 70 74 65 6c 65 6d } //01 00  Pickup_Moeglich_Optelem
		$a_00_10 = {49 73 42 61 64 43 6f 64 65 50 74 72 } //01 00  IsBadCodePtr
		$a_00_11 = {52 65 73 75 6d 65 54 68 72 65 61 64 } //01 00  ResumeThread
		$a_01_12 = {43 72 65 61 74 65 54 68 72 65 61 64 } //01 00  CreateThread
		$a_00_13 = {43 72 65 61 74 65 4d 75 74 65 78 41 } //01 00  CreateMutexA
		$a_00_14 = {49 73 42 61 64 57 72 69 74 65 50 74 72 } //01 00  IsBadWritePtr
		$a_00_15 = {43 72 65 61 74 65 50 72 6f 63 65 73 73 41 } //01 00  CreateProcessA
		$a_00_16 = {47 65 74 4c 61 73 74 41 63 74 69 76 65 50 6f 70 75 70 } //01 00  GetLastActivePopup
		$a_01_17 = {47 65 74 53 79 73 74 65 6d 44 69 72 65 63 74 6f 72 79 41 } //01 00  GetSystemDirectoryA
		$a_00_18 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //01 00  Software\Microsoft\Windows\CurrentVersion\Run
		$a_00_19 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 45 78 70 6c 6f 72 65 72 5c 53 68 65 6c 6c 20 46 6f 6c 64 65 72 73 } //01 00  Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders
		$a_00_20 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 53 68 65 6c 6c 53 65 72 76 69 63 65 4f 62 6a 65 63 74 44 65 6c 61 79 4c 6f 61 64 } //00 00  Software\Microsoft\Windows\CurrentVersion\ShellServiceObjectDelayLoad
	condition:
		any of ($a_*)
 
}