
rule Backdoor_Win32_Bifrose_AE{
	meta:
		description = "Backdoor:Win32/Bifrose.AE,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {43 00 3a 00 5c 00 55 00 73 00 65 00 72 00 73 00 5c 00 37 00 4d 00 6f 00 6f 00 44 00 69 00 5c 00 44 00 65 00 73 00 6b 00 74 00 6f 00 70 00 5c 00 53 00 5c 00 50 00 72 00 6f 00 6a 00 65 00 63 00 74 00 31 00 2e 00 76 00 62 00 70 00 } //01 00  C:\Users\7MooDi\Desktop\S\Project1.vbp
		$a_01_1 = {43 30 6e 76 33 52 74 } //01 00  C0nv3Rt
		$a_03_2 = {43 00 3c 00 72 90 01 03 65 90 01 03 61 90 01 03 74 90 01 03 65 90 01 03 50 90 01 03 72 90 01 03 6f 90 01 03 63 90 01 03 65 90 01 03 73 90 01 03 73 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Backdoor_Win32_Bifrose_AE_2{
	meta:
		description = "Backdoor:Win32/Bifrose.AE,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 11 00 00 01 00 "
		
	strings :
		$a_01_0 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 41 70 70 20 50 61 74 68 73 5c 69 65 78 70 6c 6f 72 65 2e 65 78 65 } //01 00  SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\iexplore.exe
		$a_01_1 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 41 63 74 69 76 65 20 53 65 74 75 70 5c 49 6e 73 74 61 6c 6c 65 64 20 43 6f 6d 70 6f 6e 65 6e 74 73 5c 25 73 } //01 00  SOFTWARE\Microsoft\Active Setup\Installed Components\%s
		$a_01_2 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //01 00  SOFTWARE\Microsoft\Windows\CurrentVersion\Run
		$a_01_3 = {53 4f 46 54 57 41 52 45 5c 43 6c 61 73 73 65 73 5c 48 54 54 50 5c 73 68 65 6c 6c 5c 6f 70 65 6e 5c 63 6f 6d 6d 61 6e 64 } //01 00  SOFTWARE\Classes\HTTP\shell\open\command
		$a_01_4 = {42 69 66 72 6f 73 74 20 52 65 6d 6f 74 65 20 43 6f 6e 74 72 6f 6c 6c 65 72 } //01 00  Bifrost Remote Controller
		$a_01_5 = {63 61 70 47 65 74 44 72 69 76 65 72 44 65 73 63 72 69 70 74 69 6f 6e 41 } //01 00  capGetDriverDescriptionA
		$a_01_6 = {63 61 70 43 72 65 61 74 65 43 61 70 74 75 72 65 57 69 6e 64 6f 77 41 } //01 00  capCreateCaptureWindowA
		$a_01_7 = {5a 77 57 72 69 74 65 56 69 72 74 75 61 6c 4d 65 6d 6f 72 79 } //01 00  ZwWriteVirtualMemory
		$a_01_8 = {43 72 65 61 74 65 52 65 6d 6f 74 65 54 68 72 65 61 64 } //01 00  CreateRemoteThread
		$a_01_9 = {49 6e 74 65 72 6e 65 74 52 65 61 64 46 69 6c 65 } //01 00  InternetReadFile
		$a_01_10 = {53 65 44 65 62 75 67 50 72 69 76 69 6c 65 67 65 } //01 00  SeDebugPrivilege
		$a_01_11 = {5a 77 43 72 65 61 74 65 54 68 72 65 61 64 } //01 00  ZwCreateThread
		$a_01_12 = {74 6f 72 53 68 75 74 64 6f 77 6e } //01 00  torShutdown
		$a_01_13 = {75 6d 78 74 72 61 79 2e 65 78 65 } //01 00  umxtray.exe
		$a_01_14 = {6b 61 76 73 76 63 2e 65 78 65 } //01 00  kavsvc.exe
		$a_01_15 = {49 73 4e 54 41 64 6d 69 6e } //01 00  IsNTAdmin
		$a_01_16 = {74 6f 72 57 72 69 74 65 } //00 00  torWrite
	condition:
		any of ($a_*)
 
}