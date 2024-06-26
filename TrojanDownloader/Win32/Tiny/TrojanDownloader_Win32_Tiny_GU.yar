
rule TrojanDownloader_Win32_Tiny_GU{
	meta:
		description = "TrojanDownloader:Win32/Tiny.GU,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 0a 00 00 01 00 "
		
	strings :
		$a_00_0 = {4d 6f 7a 69 6c 6c 61 2f 35 2e 30 } //01 00  Mozilla/5.0
		$a_00_1 = {50 65 72 6d 69 73 73 69 6f 6e 44 6c 67 } //01 00  PermissionDlg
		$a_00_2 = {57 61 72 6e 69 6e 67 3a 20 43 6f 6d 70 6f 6e 65 6e 74 73 20 48 61 76 65 20 43 68 61 6e 67 65 64 } //01 00  Warning: Components Have Changed
		$a_00_3 = {48 69 64 64 65 6e 20 50 72 6f 63 65 73 73 20 52 65 71 75 65 73 74 73 20 4e 65 74 77 6f 72 6b 20 41 63 63 65 73 73 } //01 00  Hidden Process Requests Network Access
		$a_00_4 = {57 69 6e 64 6f 77 73 20 53 65 63 75 72 69 74 79 20 41 6c 65 72 74 } //01 00  Windows Security Alert
		$a_00_5 = {41 6c 6c 6f 77 20 61 6c 6c 20 61 63 74 69 76 69 74 69 65 73 20 66 6f 72 20 74 68 69 73 20 61 70 70 6c 69 63 61 74 69 6f 6e } //01 00  Allow all activities for this application
		$a_00_6 = {43 72 65 61 74 65 20 72 75 6c 65 20 66 6f 72 20 25 73 } //01 00  Create rule for %s
		$a_00_7 = {41 6e 56 69 72 20 54 61 73 6b 20 4d 61 6e 61 67 65 72 } //01 00  AnVir Task Manager
		$a_00_8 = {77 69 6e 33 32 2e 65 78 65 } //01 00  win32.exe
		$a_02_9 = {43 3a 5c 54 45 4d 50 5c 73 76 63 68 90 02 01 73 74 2e 65 78 65 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}