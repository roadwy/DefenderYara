
rule Worm_Win32_Autorun_DZ{
	meta:
		description = "Worm:Win32/Autorun.DZ,SIGNATURE_TYPE_PEHSTR,08 00 08 00 08 00 00 "
		
	strings :
		$a_01_0 = {32 62 66 34 31 30 37 32 2d 62 32 62 31 2d 32 31 63 31 2d 62 35 63 31 2d 30 33 30 35 66 34 31 35 35 35 31 35 } //1 2bf41072-b2b1-21c1-b5c1-0305f4155515
		$a_01_1 = {41 75 74 6f 52 75 6e 2e 69 6e 66 } //1 AutoRun.inf
		$a_01_2 = {5b 41 75 74 6f 52 75 6e 5d } //1 [AutoRun]
		$a_01_3 = {73 68 65 6c 6c 5c 6f 70 65 6e 5c 43 6f 6d 6d 61 6e 64 } //1 shell\open\Command
		$a_01_4 = {48 69 64 65 46 69 6c 65 45 78 74 } //1 HideFileExt
		$a_01_5 = {53 68 6f 77 53 75 70 65 72 48 69 64 64 65 6e } //1 ShowSuperHidden
		$a_01_6 = {49 6e 74 65 72 6e 65 74 52 65 61 64 46 69 6c 65 } //1 InternetReadFile
		$a_01_7 = {57 69 6e 45 78 65 63 } //1 WinExec
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=8
 
}