
rule Worm_Win32_Autorun_EE{
	meta:
		description = "Worm:Win32/Autorun.EE,SIGNATURE_TYPE_PEHSTR,08 00 08 00 08 00 00 "
		
	strings :
		$a_01_0 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //1 SOFTWARE\Microsoft\Windows\CurrentVersion\Run
		$a_01_1 = {4d 69 73 56 68 35 35 2e 65 78 65 } //1 MisVh55.exe
		$a_01_2 = {4e 6f 52 75 6e } //1 NoRun
		$a_01_3 = {4e 6f 46 6f 6c 64 65 72 4f 70 74 69 6f 6e 73 } //1 NoFolderOptions
		$a_01_4 = {44 69 73 61 62 6c 65 52 65 67 69 73 74 72 79 54 6f 6f 6c 73 } //1 DisableRegistryTools
		$a_01_5 = {46 69 63 68 69 65 72 73 2e 65 78 65 } //1 Fichiers.exe
		$a_01_6 = {53 61 76 65 73 2e 65 78 65 } //1 Saves.exe
		$a_01_7 = {34 35 30 44 38 46 42 41 2d 41 44 32 35 2d 31 31 44 30 2d 39 38 41 38 2d 30 38 30 30 33 36 31 42 31 31 30 33 } //1 450D8FBA-AD25-11D0-98A8-0800361B1103
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=8
 
}