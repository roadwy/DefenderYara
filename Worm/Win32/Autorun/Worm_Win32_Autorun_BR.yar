
rule Worm_Win32_Autorun_BR{
	meta:
		description = "Worm:Win32/Autorun.BR,SIGNATURE_TYPE_PEHSTR_EXT,3d 01 3d 01 0b 00 00 "
		
	strings :
		$a_00_0 = {53 4f 46 54 57 41 52 45 5c 42 6f 72 6c 61 6e 64 5c 44 65 6c 70 68 69 5c 52 54 4c } //100 SOFTWARE\Borland\Delphi\RTL
		$a_00_1 = {55 72 6c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 } //100 UrlDownloadToFileA
		$a_02_2 = {68 74 74 70 3a 2f 2f [0-30] 2e 65 78 65 } //10
		$a_00_3 = {5c 43 24 5c 53 65 74 75 70 2e 65 78 65 } //1 \C$\Setup.exe
		$a_00_4 = {5c 43 24 5c 41 75 74 6f 45 78 65 63 2e 62 61 74 } //1 \C$\AutoExec.bat
		$a_00_5 = {5c 41 75 74 6f 52 75 6e 2e 69 6e 66 } //1 \AutoRun.inf
		$a_00_6 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 50 6f 6c 69 63 69 65 73 5c 45 78 70 6c 6f 72 65 72 } //1 Software\Microsoft\Windows\CurrentVersion\Policies\Explorer
		$a_00_7 = {4e 6f 44 72 69 76 65 54 79 70 65 41 75 74 6f 52 75 6e } //1 NoDriveTypeAutoRun
		$a_00_8 = {5b 41 75 74 6f 52 75 6e 5d } //1 [AutoRun]
		$a_01_9 = {6f 70 65 6e 3d } //1 open=
		$a_02_10 = {33 c9 51 51 51 51 51 51 33 c0 55 68 ?? ?? ?? ?? 64 ff 30 64 89 20 6a 00 6a 00 8d 45 fc e8 ?? ?? ?? ?? 8d 45 fc 50 8d 45 f4 8b 15 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b 45 f4 8d 55 f8 e8 ?? ?? ?? ?? 8b 55 f8 58 e8 ?? ?? ?? ?? 8b 45 fc e8 ?? ?? ?? ?? 50 a1 ?? ?? ?? ?? 50 6a 00 e8 ?? ?? ?? ?? 85 c0 75 3e 6a 01 8d 45 f0 } //100
	condition:
		((#a_00_0  & 1)*100+(#a_00_1  & 1)*100+(#a_02_2  & 1)*10+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1+(#a_00_7  & 1)*1+(#a_00_8  & 1)*1+(#a_01_9  & 1)*1+(#a_02_10  & 1)*100) >=317
 
}