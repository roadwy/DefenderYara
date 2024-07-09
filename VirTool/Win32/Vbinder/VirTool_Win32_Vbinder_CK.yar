
rule VirTool_Win32_Vbinder_CK{
	meta:
		description = "VirTool:Win32/Vbinder.CK,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 06 00 00 "
		
	strings :
		$a_01_0 = {b9 59 00 00 00 ff d6 8d 4d dc 88 45 dc 51 e8 } //2
		$a_01_1 = {b9 50 00 00 00 ff d6 8d 55 dc 88 45 dc 52 e8 } //2
		$a_03_2 = {3d 4d 5a 00 00 0f 85 ?? ?? 00 00 83 ?? 3c 6a 04 } //1
		$a_03_3 = {8b 4d 08 8b 11 2b d6 70 ?? 2b d0 } //2
		$a_00_4 = {4e 00 74 00 57 00 72 00 69 00 74 00 65 00 56 00 69 00 72 00 74 00 75 00 61 00 6c 00 4d 00 65 00 6d 00 6f 00 72 00 79 00 } //1 NtWriteVirtualMemory
		$a_00_5 = {4e 00 74 00 55 00 6e 00 6d 00 61 00 70 00 56 00 69 00 65 00 77 00 4f 00 66 00 53 00 65 00 63 00 74 00 69 00 6f 00 6e 00 } //1 NtUnmapViewOfSection
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_03_2  & 1)*1+(#a_03_3  & 1)*2+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1) >=7
 
}