
rule PWS_Win32_OnLineGames_DI{
	meta:
		description = "PWS:Win32/OnLineGames.DI,SIGNATURE_TYPE_PEHSTR,47 00 45 00 0e 00 00 "
		
	strings :
		$a_01_0 = {53 4f 46 54 57 41 52 45 5c 42 6f 72 6c 61 6e 64 5c 44 65 6c 70 68 69 5c 52 54 4c } //20 SOFTWARE\Borland\Delphi\RTL
		$a_01_1 = {52 65 67 52 65 73 74 6f 72 65 4b 65 79 41 } //20 RegRestoreKeyA
		$a_01_2 = {53 65 74 53 65 63 75 72 69 74 79 49 6e 66 6f } //20 SetSecurityInfo
		$a_01_3 = {5c 69 75 6f 69 75 6f 5c 73 79 73 75 74 69 6c 73 2e 70 61 73 } //1 \iuoiuo\sysutils.pas
		$a_01_4 = {63 3a 5c 36 37 35 36 72 72 74 79 2e 74 78 74 } //1 c:\6756rrty.txt
		$a_01_5 = {73 79 73 74 65 6d 6c 66 2e 64 6c 6c } //1 systemlf.dll
		$a_01_6 = {73 79 73 77 69 6e 2e 73 79 73 } //1 syswin.sys
		$a_01_7 = {53 74 61 72 74 48 6f 6f 6b } //1 StartHook
		$a_01_8 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 70 6f 6c 69 63 69 65 73 5c 45 78 70 6c 6f 72 65 72 5c 52 75 6e } //1 SOFTWARE\Microsoft\Windows\CurrentVersion\policies\Explorer\Run
		$a_01_9 = {5f 64 65 6c 65 74 65 6d 65 2e 62 61 74 } //1 _deleteme.bat
		$a_01_10 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //1 Software\Microsoft\Windows\CurrentVersion\Run
		$a_01_11 = {69 6f 37 69 74 75 37 74 66 79 74 } //1 io7itu7tfyt
		$a_01_12 = {73 79 73 67 72 77 2e 65 78 65 } //1 sysgrw.exe
		$a_01_13 = {5c 00 44 00 65 00 76 00 69 00 63 00 65 00 5c 00 50 00 68 00 79 00 73 00 69 00 63 00 61 00 6c 00 4d 00 65 00 6d 00 6f 00 72 00 79 00 } //1 \Device\PhysicalMemory
	condition:
		((#a_01_0  & 1)*20+(#a_01_1  & 1)*20+(#a_01_2  & 1)*20+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1+(#a_01_12  & 1)*1+(#a_01_13  & 1)*1) >=69
 
}
rule PWS_Win32_OnLineGames_DI_2{
	meta:
		description = "PWS:Win32/OnLineGames.DI,SIGNATURE_TYPE_PEHSTR,72 00 6f 00 13 00 00 "
		
	strings :
		$a_01_0 = {53 4f 46 54 57 41 52 45 5c 42 6f 72 6c 61 6e 64 5c 44 65 6c 70 68 69 5c 52 54 4c } //20 SOFTWARE\Borland\Delphi\RTL
		$a_01_1 = {54 6f 6f 6c 68 65 6c 70 33 32 52 65 61 64 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //20 Toolhelp32ReadProcessMemory
		$a_01_2 = {50 72 6f 63 65 73 73 33 32 4e 65 78 74 } //20 Process32Next
		$a_01_3 = {45 6e 75 6d 43 61 6c 65 6e 64 61 72 49 6e 66 6f 41 } //20 EnumCalendarInfoA
		$a_01_4 = {67 65 74 68 6f 73 74 62 79 6e 61 6d 65 } //20 gethostbyname
		$a_01_5 = {5c 69 75 6f 69 75 6f 5c 73 79 73 75 74 69 6c 73 2e 70 61 73 } //1 \iuoiuo\sysutils.pas
		$a_01_6 = {63 3a 5c 78 78 32 36 2e 74 78 74 } //1 c:\xx26.txt
		$a_01_7 = {75 73 72 5c 61 6c 6c 5c 6c 6f 67 69 6e 5f 77 2e 62 69 6e } //1 usr\all\login_w.bin
		$a_01_8 = {70 61 73 73 6d 65 6d 3a } //1 passmem:
		$a_01_9 = {3f 70 61 73 73 6d 65 6d 3d } //1 ?passmem=
		$a_01_10 = {26 62 69 6e 66 69 6c 65 3d } //1 &binfile=
		$a_01_11 = {26 62 69 6e 64 61 74 61 3d } //1 &bindata=
		$a_01_12 = {26 66 69 72 73 74 62 69 6e 3d } //1 &firstbin=
		$a_01_13 = {43 3a 5c 78 78 62 69 69 6e 2e 62 69 6e } //1 C:\xxbiin.bin
		$a_01_14 = {36 37 35 36 72 72 74 79 6d 61 70 66 69 6c 65 } //1 6756rrtymapfile
		$a_01_15 = {63 3a 5c 36 37 35 36 72 72 74 79 2e 74 78 74 } //1 c:\6756rrty.txt
		$a_01_16 = {70 6f 6c 2e 65 78 65 } //1 pol.exe
		$a_01_17 = {53 74 61 72 74 48 6f 6f 6b } //1 StartHook
		$a_01_18 = {6a 70 66 66 31 31 2e 64 6c 6c } //1 jpff11.dll
	condition:
		((#a_01_0  & 1)*20+(#a_01_1  & 1)*20+(#a_01_2  & 1)*20+(#a_01_3  & 1)*20+(#a_01_4  & 1)*20+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1+(#a_01_12  & 1)*1+(#a_01_13  & 1)*1+(#a_01_14  & 1)*1+(#a_01_15  & 1)*1+(#a_01_16  & 1)*1+(#a_01_17  & 1)*1+(#a_01_18  & 1)*1) >=111
 
}