
rule VirTool_Win32_AvetDllInject_G_MTB{
	meta:
		description = "VirTool:Win32/AvetDllInject.G!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 04 00 00 "
		
	strings :
		$a_00_0 = {6c 69 62 67 63 6a 2d 31 36 2e 64 6c 6c } //2 libgcj-16.dll
		$a_02_1 = {65 78 65 63 5f 63 61 6c 63 [0-02] 2e 64 6c 6c } //2
		$a_80_2 = {57 49 4e 44 4f 57 53 5c 73 79 73 74 65 6d 33 32 5c 63 6d 64 2e 65 78 65 } //WINDOWS\system32\cmd.exe  2
		$a_02_3 = {00 00 b8 01 00 00 00 90 09 03 00 e8 } //2
	condition:
		((#a_00_0  & 1)*2+(#a_02_1  & 1)*2+(#a_80_2  & 1)*2+(#a_02_3  & 1)*2) >=8
 
}