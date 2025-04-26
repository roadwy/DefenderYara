
rule Trojan_Win32_Delf_AT_MTB{
	meta:
		description = "Trojan:Win32/Delf.AT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 07 00 00 "
		
	strings :
		$a_80_0 = {64 65 6c 20 22 43 3a 5c 6d 79 61 70 70 2e 65 78 65 22 20 2f 71 } //del "C:\myapp.exe" /q  3
		$a_80_1 = {69 66 20 65 78 69 73 74 20 22 43 3a 5c 6d 79 61 70 70 2e 65 78 65 22 20 67 6f 74 6f 20 74 72 79 } //if exist "C:\myapp.exe" goto try  3
		$a_80_2 = {57 69 6e 45 78 65 63 } //WinExec  3
		$a_80_3 = {47 65 74 56 6f 6c 75 6d 65 49 6e 66 6f 72 6d 61 74 69 6f 6e 41 } //GetVolumeInformationA  3
		$a_80_4 = {47 65 74 53 74 61 72 74 75 70 49 6e 66 6f 41 } //GetStartupInfoA  3
		$a_80_5 = {47 65 74 4b 65 79 62 6f 61 72 64 54 79 70 65 } //GetKeyboardType  3
		$a_80_6 = {47 65 74 43 6f 6d 6d 61 6e 64 4c 69 6e 65 41 } //GetCommandLineA  3
	condition:
		((#a_80_0  & 1)*3+(#a_80_1  & 1)*3+(#a_80_2  & 1)*3+(#a_80_3  & 1)*3+(#a_80_4  & 1)*3+(#a_80_5  & 1)*3+(#a_80_6  & 1)*3) >=21
 
}