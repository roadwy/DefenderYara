
rule Trojan_Win32_Tnega_A_MTB{
	meta:
		description = "Trojan:Win32/Tnega.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,12 00 12 00 06 00 00 "
		
	strings :
		$a_81_0 = {63 6d 64 2e 65 78 65 20 2f 63 20 70 6f 77 65 72 73 68 65 6c 6c 2e 65 78 65 20 2d 77 69 6e 64 6f 77 73 74 79 6c 65 20 68 69 64 64 65 6e 20 53 6c 65 65 70 20 35 } //3 cmd.exe /c powershell.exe -windowstyle hidden Sleep 5
		$a_81_1 = {53 65 6e 64 4e 6f 74 69 66 79 4d 65 73 73 61 67 65 41 } //3 SendNotifyMessageA
		$a_81_2 = {47 65 74 43 6f 6d 6d 61 6e 64 4c 69 6e 65 57 } //3 GetCommandLineW
		$a_81_3 = {6a 62 66 65 63 61 72 67 61 77 73 62 6d } //3 jbfecargawsbm
		$a_81_4 = {43 72 65 61 74 65 46 69 6c 65 57 } //3 CreateFileW
		$a_81_5 = {57 72 69 74 65 43 6f 6e 73 6f 6c 65 57 } //3 WriteConsoleW
	condition:
		((#a_81_0  & 1)*3+(#a_81_1  & 1)*3+(#a_81_2  & 1)*3+(#a_81_3  & 1)*3+(#a_81_4  & 1)*3+(#a_81_5  & 1)*3) >=18
 
}