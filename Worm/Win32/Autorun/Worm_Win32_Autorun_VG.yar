
rule Worm_Win32_Autorun_VG{
	meta:
		description = "Worm:Win32/Autorun.VG,SIGNATURE_TYPE_PEHSTR,06 00 05 00 09 00 00 "
		
	strings :
		$a_01_0 = {22 36 31 33 33 36 35 35 32 37 37 39 34 38 32 22 } //1 "61336552779482"
		$a_01_1 = {22 5c 59 61 68 6f 6f 21 20 76 69 64 65 6f 20 63 68 61 74 2e 65 78 65 22 29 } //1 "\Yahoo! video chat.exe")
		$a_01_2 = {2e 77 72 69 74 65 6c 69 6e 65 20 22 4f 70 65 6e 3d 32 37 37 39 5c 53 43 41 4e 4e 49 4e 47 2e 45 58 45 22 } //1 .writeline "Open=2779\SCANNING.EXE"
		$a_01_3 = {2e 46 69 6c 65 45 78 69 73 74 73 28 22 63 3a 5c 32 37 37 39 5c 44 65 73 6b 74 6f 70 2e 69 6e 69 22 29 } //1 .FileExists("c:\2779\Desktop.ini")
		$a_01_4 = {2e 72 65 67 77 72 69 74 65 20 22 48 4b 45 59 5f 4c 4f 43 41 4c 5f 4d 41 43 48 49 4e 45 5c 53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e 5c 44 54 43 49 22 } //1 .regwrite "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run\DTCI"
		$a_01_5 = {2e 77 72 69 74 65 6c 69 6e 65 20 22 43 4c 53 49 44 3d 7b 36 34 35 46 46 30 34 30 2d 35 30 38 31 2d 31 30 31 42 2d 39 46 30 38 2d 30 30 41 41 30 30 32 46 39 35 34 45 7d 22 } //1 .writeline "CLSID={645FF040-5081-101B-9F08-00AA002F954E}"
		$a_01_6 = {2e 77 72 69 74 65 6c 69 6e 65 20 22 5b 41 75 74 6f 72 75 6e 5d 22 } //1 .writeline "[Autorun]"
		$a_01_7 = {67 65 74 6f 62 6a 65 63 74 28 22 77 69 6e 6d 67 6d 74 73 3a 22 26 22 7b 69 6d 70 65 72 73 6f 6e 61 74 69 6f 6e 4c 65 76 65 6c 3d 69 6d 70 65 72 73 6f 6e 61 74 65 7d 21 5c 5c 22 } //1 getobject("winmgmts:"&"{impersonationLevel=impersonate}!\\"
		$a_01_8 = {67 65 74 6f 62 6a 65 63 74 28 22 57 69 6e 4e 54 3a 2f 2f 2e 2f 22 26 69 26 22 2c 75 73 65 72 22 29 } //1 getobject("WinNT://./"&i&",user")
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1) >=5
 
}