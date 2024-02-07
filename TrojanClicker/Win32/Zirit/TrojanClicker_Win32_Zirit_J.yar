
rule TrojanClicker_Win32_Zirit_J{
	meta:
		description = "TrojanClicker:Win32/Zirit.J,SIGNATURE_TYPE_PEHSTR_EXT,05 00 04 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {83 c4 08 8b d8 ff 15 58 d0 00 10 50 8d 4c 24 74 68 2c f2 00 10 } //01 00 
		$a_01_1 = {76 33 2e 6d 61 69 6e 66 65 65 64 68 65 72 65 2e 63 6f 6d 00 65 78 65 63 00 00 00 00 63 6c 69 63 6b 73 00 00 75 72 6c 00 64 6e 73 } //01 00 
		$a_00_2 = {25 6c 64 2e 65 78 65 } //01 00  %ld.exe
		$a_00_3 = {70 69 64 3d 25 73 26 73 3d 25 73 26 76 3d 31 31 26 75 73 65 72 3d 25 73 26 64 61 74 65 3d 25 73 26 71 3d 25 73 } //01 00  pid=%s&s=%s&v=11&user=%s&date=%s&q=%s
		$a_00_4 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 53 68 65 6c 6c 53 65 72 76 69 63 65 4f 62 6a 65 63 74 44 65 6c 61 79 4c 6f 61 64 } //01 00  SOFTWARE\Microsoft\Windows\CurrentVersion\ShellServiceObjectDelayLoad
		$a_02_5 = {8b f0 83 fe ff 74 90 01 01 8d 44 24 10 50 56 ff 15 90 01 03 10 90 02 02 83 c0 da 90 02 02 50 56 ff 15 90 01 03 10 8d 4c 24 0c 90 02 02 51 6a 26 68 90 01 03 10 56 ff 15 90 01 03 10 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}