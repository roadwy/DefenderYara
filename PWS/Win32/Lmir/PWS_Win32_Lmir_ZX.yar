
rule PWS_Win32_Lmir_ZX{
	meta:
		description = "PWS:Win32/Lmir.ZX,SIGNATURE_TYPE_PEHSTR_EXT,4a 00 4a 00 05 00 00 32 00 "
		
	strings :
		$a_00_0 = {31 41 34 30 34 36 38 35 2d 37 35 36 33 2d 34 64 30 32 2d 42 30 46 36 2d 35 38 42 33 30 38 41 34 30 36 41 39 } //14 00  1A404685-7563-4d02-B0F6-58B308A406A9
		$a_01_1 = {43 72 65 61 74 65 52 65 6d 6f 74 65 54 68 72 65 61 64 } //04 00  CreateRemoteThread
		$a_00_2 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 45 78 70 6c 6f 72 65 72 5c 53 68 65 6c 6c 45 78 65 63 75 74 65 48 6f 6f 6b 73 } //04 00  SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ShellExecuteHooks
		$a_00_3 = {63 6c 69 65 6e 74 2e 65 78 65 } //04 00  client.exe
		$a_00_4 = {53 72 76 48 6f 73 74 2e 64 6c 6c } //00 00  SrvHost.dll
	condition:
		any of ($a_*)
 
}
rule PWS_Win32_Lmir_ZX_2{
	meta:
		description = "PWS:Win32/Lmir.ZX,SIGNATURE_TYPE_PEHSTR_EXT,10 00 0f 00 0a 00 00 04 00 "
		
	strings :
		$a_01_0 = {59 42 5f 4f 6e 6c 69 6e 65 43 6c 69 65 6e 74 } //03 00  YB_OnlineClient
		$a_00_1 = {41 63 63 65 70 74 2d 4c 61 6e 67 75 61 67 65 3a 20 7a 68 2d 63 6e } //03 00  Accept-Language: zh-cn
		$a_01_2 = {53 65 44 65 62 75 67 50 72 69 76 69 6c 65 67 65 } //01 00  SeDebugPrivilege
		$a_00_3 = {48 6f 73 74 3a 20 25 73 } //02 00  Host: %s
		$a_00_4 = {51 45 6c 65 6d 65 6e 74 43 6c 69 65 6e 74 } //01 00  QElementClient
		$a_00_5 = {50 61 73 73 3d } //01 00  Pass=
		$a_00_6 = {55 73 65 72 3d } //01 00  User=
		$a_00_7 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c } //01 00  SOFTWARE\Microsoft\Windows\
		$a_00_8 = {73 75 62 6a 65 63 74 } //01 00  subject
		$a_01_9 = {43 72 65 61 74 65 54 6f 6f 6c 68 65 6c 70 33 32 53 6e 61 70 73 68 6f 74 } //00 00  CreateToolhelp32Snapshot
	condition:
		any of ($a_*)
 
}