
rule Worm_Win32_Autorun_AAK{
	meta:
		description = "Worm:Win32/Autorun.AAK,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 04 00 00 "
		
	strings :
		$a_01_0 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 20 4e 54 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 49 6d 61 67 65 20 46 69 6c 65 20 45 78 65 63 75 74 69 6f 6e 20 4f 70 74 69 6f 6e 73 5c 54 72 6f 6a 61 6e 44 65 74 65 63 74 6f 72 2e 65 78 65 5c 44 65 62 75 67 67 65 72 } //2 SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\TrojanDetector.exe\Debugger
		$a_01_1 = {63 68 74 64 6c 6c 2e 64 6c 6c } //2 chtdll.dll
		$a_01_2 = {67 67 5f 66 69 6c 65 } //1 gg_file
		$a_01_3 = {6e 65 74 2e 65 78 65 20 73 74 6f 70 20 } //1 net.exe stop 
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=6
 
}