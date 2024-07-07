
rule TrojanDropper_Win32_QQpass_gen_D{
	meta:
		description = "TrojanDropper:Win32/QQpass.gen!D,SIGNATURE_TYPE_PEHSTR_EXT,46 00 32 00 1a 00 00 "
		
	strings :
		$a_01_0 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 45 78 70 6c 6f 72 65 72 5c 53 68 65 6c 6c 45 78 65 63 75 74 65 48 6f 6f 6b 73 } //3 SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ShellExecuteHooks
		$a_01_1 = {3a 5c 50 72 6f 67 72 61 6d 20 46 69 6c 65 73 5c 43 6f 6d 6d 6f 6e 20 46 69 6c 65 73 5c 4d 69 63 72 6f 73 6f 66 74 20 53 68 61 72 65 64 5c 4d 53 49 4e 46 4f 5c } //2 :\Program Files\Common Files\Microsoft Shared\MSINFO\
		$a_01_2 = {4a 6d 70 48 6f 6f 6b 4f 6e } //3 JmpHookOn
		$a_01_3 = {4a 6d 70 48 6f 6f 6b 4f 66 66 } //2 JmpHookOff
		$a_01_4 = {44 4c 4c 46 49 4c 45 } //1 DLLFILE
		$a_01_5 = {5c 49 6e 50 72 6f 63 53 65 72 76 65 72 33 32 } //1 \InProcServer32
		$a_01_6 = {64 65 6c 20 25 30 } //1 del %0
		$a_01_7 = {54 68 72 65 61 64 69 6e 67 4d 6f 64 65 6c } //1 ThreadingModel
		$a_01_8 = {41 70 61 72 74 6d 65 6e 74 } //1 Apartment
		$a_01_9 = {20 67 6f 74 6f 20 74 72 79 } //1  goto try
		$a_01_10 = {65 72 76 65 72 33 32 } //3 erver32
		$a_01_11 = {53 48 4c 57 41 50 49 2e 44 4c 4c } //1 SHLWAPI.DLL
		$a_01_12 = {77 69 6e 69 6e 69 74 2e 69 6e 69 } //2 wininit.ini
		$a_01_13 = {4c 69 73 74 42 6f 78 } //1 ListBox
		$a_01_14 = {64 65 6c 20 22 } //1 del "
		$a_01_15 = {69 66 20 65 78 69 73 74 20 22 } //1 if exist "
		$a_01_16 = {5a 58 59 5f 77 66 67 51 51 } //10 ZXY_wfgQQ
		$a_01_17 = {53 79 73 57 46 47 51 51 32 2e 64 6c 6c } //5 SysWFGQQ2.dll
		$a_01_18 = {5f 78 72 2e 62 61 74 } //10 _xr.bat
		$a_01_19 = {43 3a 5c 50 72 6f 67 72 61 6d 20 46 69 6c 65 73 5c 43 6f 6d 6d 6f 6e 20 46 69 6c 65 73 5c 4d 69 63 72 6f 73 6f 66 74 20 53 68 61 72 65 64 5c 4d 53 49 4e 46 4f 5c 53 79 73 57 46 47 51 51 2e 64 6c 6c } //10 C:\Program Files\Common Files\Microsoft Shared\MSINFO\SysWFGQQ.dll
		$a_01_20 = {2d 7a 2a 74 6b } //5 -z*tk
		$a_01_21 = {43 3a 5c 50 72 6f 67 72 61 6d 20 46 69 6c 65 73 5c 43 6f 6d 6d 6f 6e 20 46 69 6c 65 73 5c 4d 69 63 72 6f 73 6f 66 74 20 53 68 61 72 65 64 5c 4d 53 49 4e 46 4f 5c 53 79 73 57 46 47 51 51 32 2e 64 6c 6c } //10 C:\Program Files\Common Files\Microsoft Shared\MSINFO\SysWFGQQ2.dll
		$a_01_22 = {43 3a 5c 5f 78 72 2e 62 61 74 } //5 C:\_xr.bat
		$a_01_23 = {53 79 73 57 46 47 51 51 2e 64 6c 6c } //5 SysWFGQQ.dll
		$a_01_24 = {7b 39 31 42 31 45 38 34 36 2d 32 42 45 46 2d 34 33 34 35 2d 38 38 34 38 2d 37 36 39 39 43 37 43 39 39 33 35 46 7d } //10 {91B1E846-2BEF-4345-8848-7699C7C9935F}
		$a_01_25 = {79 6f 75 6d 65 69 79 6f 75 67 61 6f 63 75 6f } //10 youmeiyougaocuo
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*2+(#a_01_2  & 1)*3+(#a_01_3  & 1)*2+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*3+(#a_01_11  & 1)*1+(#a_01_12  & 1)*2+(#a_01_13  & 1)*1+(#a_01_14  & 1)*1+(#a_01_15  & 1)*1+(#a_01_16  & 1)*10+(#a_01_17  & 1)*5+(#a_01_18  & 1)*10+(#a_01_19  & 1)*10+(#a_01_20  & 1)*5+(#a_01_21  & 1)*10+(#a_01_22  & 1)*5+(#a_01_23  & 1)*5+(#a_01_24  & 1)*10+(#a_01_25  & 1)*10) >=50
 
}