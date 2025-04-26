
rule HackTool_Win32_NSudo_A{
	meta:
		description = "HackTool:Win32/NSudo.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 07 00 00 "
		
	strings :
		$a_80_0 = {6c 69 63 65 6e 73 65 64 20 62 79 20 44 69 6e 6b 75 6d 77 61 72 65 } //licensed by Dinkumware  1
		$a_80_1 = {68 74 74 70 73 3a 2f 2f 67 69 74 68 75 62 2e 63 6f 6d 2f 4d 32 54 65 61 6d 2f 4e 53 75 64 6f } //https://github.com/M2Team/NSudo  1
		$a_80_2 = {4e 53 75 64 6f 20 2d 55 3a 20 54 20 2d 50 3a 20 45 20 63 6d 64 } //NSudo -U: T -P: E cmd  1
		$a_80_3 = {4e 53 75 64 6f 2e 65 78 65 } //NSudo.exe  1
		$a_80_4 = {4e 53 75 64 6f 2e 4c 61 75 6e 63 68 65 72 } //NSudo.Launcher  1
		$a_80_5 = {4e 53 75 64 6f 2e 52 75 6e 41 73 2e 54 72 75 73 74 65 64 49 6e 73 74 61 6c 6c 65 72 } //NSudo.RunAs.TrustedInstaller  1
		$a_80_6 = {4e 53 75 64 6f 2e 52 75 6e 41 73 2e 53 79 73 74 65 6d 2e 45 6e 61 62 6c 65 41 6c 6c 50 72 69 76 69 6c 65 67 65 73 } //NSudo.RunAs.System.EnableAllPrivileges  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1+(#a_80_6  & 1)*1) >=3
 
}