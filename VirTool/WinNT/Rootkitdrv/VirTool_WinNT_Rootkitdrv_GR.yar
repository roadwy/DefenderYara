
rule VirTool_WinNT_Rootkitdrv_GR{
	meta:
		description = "VirTool:WinNT/Rootkitdrv.GR,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_02_0 = {c7 00 b8 01 00 00 83 c0 04 8b 08 89 0d ?? ?? ?? 00 c7 00 00 c2 08 00 } //1
		$a_00_1 = {4d 6d 47 65 74 53 79 73 74 65 6d 52 6f 75 74 69 6e 65 41 64 64 72 65 73 73 } //1 MmGetSystemRoutineAddress
		$a_00_2 = {4d 00 6d 00 46 00 6c 00 75 00 73 00 68 00 49 00 6d 00 61 00 67 00 65 00 53 00 65 00 63 00 74 00 69 00 6f 00 6e 00 } //1 MmFlushImageSection
	condition:
		((#a_02_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}