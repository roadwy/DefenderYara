
rule PWS_Win32_Zengtu_C{
	meta:
		description = "PWS:Win32/Zengtu.C,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 06 00 00 "
		
	strings :
		$a_00_0 = {7a 68 65 6e 67 74 75 } //3 zhengtu
		$a_01_1 = {53 65 44 65 62 75 67 50 72 69 76 69 6c 65 67 65 } //1 SeDebugPrivilege
		$a_00_2 = {43 6f 6e 74 65 6e 74 2d 54 79 70 65 3a } //1 Content-Type:
		$a_00_3 = {45 78 70 6c 6f 72 65 72 5c 53 68 65 6c 6c 45 78 65 63 75 74 65 48 6f 6f 6b 73 } //1 Explorer\ShellExecuteHooks
		$a_01_4 = {57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //1 WriteProcessMemory
		$a_00_5 = {50 61 73 73 3d } //1 Pass=
	condition:
		((#a_00_0  & 1)*3+(#a_01_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_01_4  & 1)*1+(#a_00_5  & 1)*1) >=8
 
}