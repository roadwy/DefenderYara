
rule VirTool_Win32_Nimboz_A_MTB{
	meta:
		description = "VirTool:Win32/Nimboz.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_02_0 = {c6 44 1c 26 40 be 63 00 00 00 41 be 0a 00 00 00 48 8d 4e 9d 48 81 fe c6 00 00 00 ?? ?? 48 83 c3 03 ?? ?? 48 8d 46 a6 48 83 f8 12 } //1
		$a_81_1 = {77 69 6e 6d 67 6d 74 73 3a 7b 69 6d 70 65 72 73 6f 6e 61 74 69 6f 6e 4c 65 76 65 6c 3d 69 6d 70 65 72 73 6f 6e 61 74 65 7d 21 5c 5c 2e 5c 72 6f 6f 74 5c 73 65 63 75 72 69 74 79 63 65 6e 74 65 72 32 } //1 winmgmts:{impersonationLevel=impersonate}!\\.\root\securitycenter2
		$a_81_2 = {72 65 67 2e 65 78 65 20 73 61 76 65 20 68 6b 6c 6d 5c 73 61 6d } //1 reg.exe save hklm\sam
		$a_81_3 = {63 6d 64 20 2f 63 20 73 64 63 6c 74 2e 65 78 65 } //1 cmd /c sdclt.exe
		$a_81_4 = {63 6d 64 20 2f 63 20 66 6f 64 68 65 6c 70 65 72 2e 65 78 65 } //1 cmd /c fodhelper.exe
	condition:
		((#a_02_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=5
 
}