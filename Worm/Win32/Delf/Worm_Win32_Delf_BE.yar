
rule Worm_Win32_Delf_BE{
	meta:
		description = "Worm:Win32/Delf.BE,SIGNATURE_TYPE_PEHSTR,2b 00 2b 00 09 00 00 "
		
	strings :
		$a_01_0 = {53 4f 46 54 57 41 52 45 5c 42 6f 72 6c 61 6e 64 5c 44 65 6c 70 68 69 5c 52 54 4c } //10 SOFTWARE\Borland\Delphi\RTL
		$a_01_1 = {2d 70 6f 72 74 20 38 30 20 2d 69 6e 73 65 72 74 20 22 3c 69 66 72 61 6d 65 20 62 6f 72 64 65 72 3d 22 30 22 20 66 72 61 6d 65 73 70 61 63 69 6e 67 3d 22 30 22 20 66 72 61 6d 65 62 6f 72 64 65 72 3d 22 30 22 20 73 63 72 6f 6c 6c 69 6e 67 3d 22 6e 6f 22 20 77 69 64 74 68 3d 22 30 22 20 68 65 69 67 68 74 3d 22 30 22 20 73 72 63 3d 22 } //10 -port 80 -insert "<iframe border="0" framespacing="0" frameborder="0" scrolling="no" width="0" height="0" src="
		$a_01_2 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 65 78 70 6c 6f 72 65 72 5c 53 68 65 6c 6c 45 78 65 63 75 74 65 48 6f 6f 6b 73 } //10 Software\Microsoft\Windows\CurrentVersion\explorer\ShellExecuteHooks
		$a_01_3 = {41 75 74 6f 72 75 6e 2e 69 6e 66 } //10 Autorun.inf
		$a_01_4 = {64 72 69 76 65 72 73 5c 6e 70 66 2e 73 79 73 } //1 drivers\npf.sys
		$a_01_5 = {54 6f 6f 6c 68 65 6c 70 33 32 52 65 61 64 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //1 Toolhelp32ReadProcessMemory
		$a_01_6 = {57 69 6e 64 6f 77 73 58 50 2e 65 78 65 } //1 WindowsXP.exe
		$a_01_7 = {45 6e 61 62 6c 65 46 69 72 65 77 61 6c 6c } //1 EnableFirewall
		$a_01_8 = {7b 41 37 38 31 41 31 45 43 2d 39 37 35 45 2d 34 37 38 38 2d 41 46 38 45 2d 41 33 46 35 35 32 44 35 35 43 34 31 7d } //1 {A781A1EC-975E-4788-AF8E-A3F552D55C41}
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*10+(#a_01_3  & 1)*10+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1) >=43
 
}