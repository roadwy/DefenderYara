
rule VirTool_Win32_VBInject_ABS{
	meta:
		description = "VirTool:Win32/VBInject.ABS,SIGNATURE_TYPE_PEHSTR_EXT,08 00 07 00 05 00 00 "
		
	strings :
		$a_03_0 = {8b 45 fc 8b 0d ?? ?? ?? ?? c7 04 c1 43 61 6c 6c c7 44 c1 04 57 69 6e 64 } //1
		$a_03_1 = {8b 45 fc 8b 0d ?? ?? ?? ?? c7 04 c1 56 69 72 74 c7 44 c1 04 75 61 6c 50 } //1
		$a_03_2 = {8b 45 fc 8b 0d ?? ?? ?? ?? c7 04 c1 6f 77 50 72 c7 44 c1 04 6f 63 57 00 } //1
		$a_03_3 = {8b 45 fc 8b 0d ?? ?? ?? ?? c7 04 c1 6c 73 74 72 c7 44 c1 04 6c 65 6e 57 } //1
		$a_00_4 = {4d 53 56 42 56 4d 36 30 2e 44 4c 4c } //4 MSVBVM60.DLL
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1+(#a_00_4  & 1)*4) >=7
 
}