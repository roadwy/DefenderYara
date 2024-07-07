
rule TrojanClicker_Win32_VB_DI{
	meta:
		description = "TrojanClicker:Win32/VB.DI,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 04 00 00 "
		
	strings :
		$a_01_0 = {4a 69 61 4d 69 53 75 62 54 65 78 74 } //4 JiaMiSubText
		$a_01_1 = {44 6f 77 6e 44 6c 6c 54 69 6d 65 72 } //2 DownDllTimer
		$a_01_2 = {77 00 69 00 6e 00 6d 00 67 00 6d 00 74 00 73 00 3a 00 7b 00 69 00 6d 00 70 00 65 00 72 00 73 00 6f 00 6e 00 61 00 74 00 69 00 6f 00 6e 00 4c 00 65 00 76 00 65 00 6c 00 3d 00 69 00 6d 00 70 00 65 00 72 00 73 00 6f 00 6e 00 61 00 74 00 65 00 7d 00 } //1 winmgmts:{impersonationLevel=impersonate}
		$a_01_3 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 } //1 URLDownloadToFileA
	condition:
		((#a_01_0  & 1)*4+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=8
 
}