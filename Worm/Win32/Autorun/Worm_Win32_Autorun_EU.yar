
rule Worm_Win32_Autorun_EU{
	meta:
		description = "Worm:Win32/Autorun.EU,SIGNATURE_TYPE_PEHSTR,0c 00 0c 00 0c 00 00 "
		
	strings :
		$a_01_0 = {50 72 6f 67 72 61 6d 20 46 69 6c 65 73 5c 43 6f 6d 6d 6f 6e 20 46 69 6c 65 73 5c 53 79 73 74 65 6d 5c 77 61 62 72 65 73 2e 64 6c 6c } //1 Program Files\Common Files\System\wabres.dll
		$a_01_1 = {36 34 35 46 46 30 34 30 2d 35 30 38 31 2d 31 30 31 42 2d 39 46 30 38 2d 30 30 41 41 30 30 32 46 39 35 34 45 } //1 645FF040-5081-101B-9F08-00AA002F954E
		$a_01_2 = {5b 61 75 74 6f 72 75 6e 5d } //1 [autorun]
		$a_01_3 = {73 68 65 6c 6c 65 78 65 63 75 74 65 3d 2e 5c 52 65 63 79 63 6c 65 64 5c 72 75 6e 64 6c 6c 33 32 2e 65 78 65 } //1 shellexecute=.\Recycled\rundll32.exe
		$a_01_4 = {41 75 74 6f 72 75 6e 2e 69 6e 66 } //1 Autorun.inf
		$a_01_5 = {52 69 63 68 65 64 33 32 2e 64 6c 6c } //1 Riched32.dll
		$a_01_6 = {50 72 6f 67 72 61 6d 5c 54 68 75 6e 64 65 72 2e 69 63 6f } //1 Program\Thunder.ico
		$a_01_7 = {53 4f 46 54 57 41 52 45 5c 54 68 75 6e 64 65 72 20 4e 65 74 77 6f 72 6b 5c 54 68 75 6e 64 65 72 4f 65 6d 5c 74 68 75 6e 64 65 72 5f 62 61 63 6b 77 6e 64 } //1 SOFTWARE\Thunder Network\ThunderOem\thunder_backwnd
		$a_01_8 = {43 72 65 61 74 65 4d 75 74 65 78 41 } //1 CreateMutexA
		$a_01_9 = {47 65 74 54 69 63 6b 43 6f 75 6e 74 } //1 GetTickCount
		$a_01_10 = {57 69 6e 45 78 65 63 } //1 WinExec
		$a_01_11 = {53 4f 46 54 57 41 52 45 5c 54 45 4e 43 45 4e 54 5c 51 51 } //1 SOFTWARE\TENCENT\QQ
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1) >=12
 
}