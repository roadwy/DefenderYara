
rule Worm_Win32_SillyShareCopy_H{
	meta:
		description = "Worm:Win32/SillyShareCopy.H,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 01 00 "
		
	strings :
		$a_01_0 = {5b 00 41 00 75 00 74 00 6f 00 52 00 75 00 6e 00 5d 00 } //01 00  [AutoRun]
		$a_01_1 = {73 00 68 00 65 00 6c 00 6c 00 5c 00 41 00 75 00 74 00 6f 00 5c 00 63 00 6f 00 6d 00 6d 00 61 00 6e 00 64 00 3d 00 } //01 00  shell\Auto\command=
		$a_01_2 = {6d 00 73 00 6e 00 6f 00 74 00 65 00 } //01 00  msnote
		$a_01_3 = {75 00 61 00 5f 00 61 00 63 00 63 00 6f 00 75 00 6e 00 74 00 20 00 6f 00 72 00 64 00 65 00 72 00 20 00 62 00 79 00 20 00 63 00 41 00 63 00 63 00 5f 00 69 00 64 00 } //01 00  ua_account order by cAcc_id
		$a_01_4 = {53 00 4f 00 46 00 54 00 57 00 41 00 52 00 45 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 43 00 75 00 72 00 72 00 65 00 6e 00 74 00 56 00 65 00 72 00 73 00 69 00 6f 00 6e 00 5c 00 45 00 78 00 70 00 6c 00 6f 00 72 00 65 00 72 00 5c 00 41 00 64 00 76 00 61 00 6e 00 63 00 65 00 64 00 5c 00 46 00 6f 00 6c 00 64 00 65 00 72 00 5c 00 48 00 69 00 64 00 64 00 65 00 6e 00 5c 00 53 00 48 00 4f 00 57 00 41 00 4c 00 4c 00 } //01 00  SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Folder\Hidden\SHOWALL
		$a_01_5 = {47 65 74 53 79 73 74 65 6d 44 69 72 65 63 74 6f 72 79 41 } //01 00  GetSystemDirectoryA
		$a_01_6 = {47 65 74 57 69 6e 64 6f 77 73 44 69 72 65 63 74 6f 72 79 41 } //01 00  GetWindowsDirectoryA
		$a_01_7 = {47 65 74 4c 6f 67 69 63 61 6c 44 72 69 76 65 53 74 72 69 6e 67 73 41 } //00 00  GetLogicalDriveStringsA
	condition:
		any of ($a_*)
 
}