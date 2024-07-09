
rule VirTool_Win32_VBInject_gen_IS{
	meta:
		description = "VirTool:Win32/VBInject.gen!IS,SIGNATURE_TYPE_PEHSTR_EXT,07 00 06 00 05 00 00 "
		
	strings :
		$a_03_0 = {66 0f b6 0c 08 8b 95 ?? ?? ff ff 8b 45 ?? 66 33 0c 50 } //2
		$a_03_1 = {8a 1c 10 03 cb 0f 80 ?? ?? ?? ?? 81 e1 ff 00 00 80 79 08 49 81 c9 00 ff ff ff 41 89 4d } //2
		$a_00_2 = {50 72 6f 6a 65 6b 74 31 } //1 Projekt1
		$a_00_3 = {46 72 61 5f 42 61 63 6b 75 70 } //1 Fra_Backup
		$a_00_4 = {57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //1 WriteProcessMemory
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=6
 
}