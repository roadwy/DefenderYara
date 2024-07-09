
rule Worm_Win32_Autorun_D{
	meta:
		description = "Worm:Win32/Autorun.D,SIGNATURE_TYPE_PEHSTR_EXT,55 00 55 00 0f 00 00 "
		
	strings :
		$a_00_0 = {48 6f 6f 6b 2e 64 6c 6c } //10 Hook.dll
		$a_00_1 = {44 6c 6c 43 61 6e 55 6e 6c 6f 61 64 4e 6f 77 } //10 DllCanUnloadNow
		$a_00_2 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } //10 DllRegisterServer
		$a_01_3 = {4d 73 67 48 6f 6f 6b 4f 66 66 } //10 MsgHookOff
		$a_01_4 = {4d 73 67 48 6f 6f 6b 4f 6e } //10 MsgHookOn
		$a_00_5 = {43 61 6c 6c 4e 65 78 74 48 6f 6f 6b 45 78 } //10 CallNextHookEx
		$a_01_6 = {49 6e 74 65 72 6e 65 74 52 65 61 64 46 69 6c 65 } //10 InternetReadFile
		$a_00_7 = {49 6e 74 65 72 6e 65 74 4f 70 65 6e } //10 InternetOpen
		$a_00_8 = {5b 61 75 74 6f 72 75 6e 5d } //1 [autorun]
		$a_00_9 = {6f 70 65 6e 3d 43 4d 44 2e 45 58 45 } //1 open=CMD.EXE
		$a_00_10 = {73 68 65 6c 6c 65 78 65 63 75 74 65 3d 43 4d 44 2e 45 58 45 } //1 shellexecute=CMD.EXE
		$a_00_11 = {73 68 65 6c 6c 5c 41 75 74 6f 5c 63 6f 6d 6d 61 6e 64 3d 43 4d 44 2e 45 58 45 } //1 shell\Auto\command=CMD.EXE
		$a_00_12 = {53 6f 66 74 77 61 72 65 5c 53 65 74 56 65 72 5c 76 65 72 } //1 Software\SetVer\ver
		$a_00_13 = {45 78 70 6c 6f 72 65 72 2e 45 78 65 } //1 Explorer.Exe
		$a_00_14 = {56 65 72 63 6c 73 69 64 2e 65 58 45 } //1 Verclsid.eXE
	condition:
		((#a_00_0  & 1)*10+(#a_00_1  & 1)*10+(#a_00_2  & 1)*10+(#a_01_3  & 1)*10+(#a_01_4  & 1)*10+(#a_00_5  & 1)*10+(#a_01_6  & 1)*10+(#a_00_7  & 1)*10+(#a_00_8  & 1)*1+(#a_00_9  & 1)*1+(#a_00_10  & 1)*1+(#a_00_11  & 1)*1+(#a_00_12  & 1)*1+(#a_00_13  & 1)*1+(#a_00_14  & 1)*1) >=85
 
}
rule Worm_Win32_Autorun_D_2{
	meta:
		description = "Worm:Win32/Autorun.D,SIGNATURE_TYPE_PEHSTR_EXT,2b 00 2b 00 07 00 00 "
		
	strings :
		$a_00_0 = {5b 00 41 00 75 00 74 00 6f 00 72 00 75 00 6e 00 5d 00 } //10 [Autorun]
		$a_00_1 = {5c 00 41 00 75 00 74 00 6f 00 72 00 75 00 6e 00 2e 00 69 00 6e 00 66 00 } //10 \Autorun.inf
		$a_02_2 = {6f 00 70 00 65 00 6e 00 3d 00 [0-20] 2e 00 65 00 78 00 65 00 } //10
		$a_00_3 = {73 00 74 00 61 00 72 00 74 00 75 00 70 00 66 00 6f 00 6c 00 64 00 65 00 72 00 2e 00 63 00 6f 00 6d 00 } //10 startupfolder.com
		$a_00_4 = {77 00 73 00 63 00 72 00 69 00 70 00 74 00 2e 00 73 00 68 00 65 00 6c 00 6c 00 } //1 wscript.shell
		$a_00_5 = {68 00 6b 00 65 00 79 00 5f 00 6c 00 6f 00 63 00 61 00 6c 00 5f 00 6d 00 61 00 63 00 68 00 69 00 6e 00 65 00 5c 00 73 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 6d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 77 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 63 00 75 00 72 00 72 00 65 00 6e 00 74 00 76 00 65 00 72 00 73 00 69 00 6f 00 6e 00 5c 00 72 00 75 00 6e 00 5c 00 } //1 hkey_local_machine\software\microsoft\windows\currentversion\run\
		$a_01_6 = {53 48 47 65 74 53 70 65 63 69 61 6c 46 6f 6c 64 65 72 4c 6f 63 61 74 69 6f 6e } //1 SHGetSpecialFolderLocation
	condition:
		((#a_00_0  & 1)*10+(#a_00_1  & 1)*10+(#a_02_2  & 1)*10+(#a_00_3  & 1)*10+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_01_6  & 1)*1) >=43
 
}