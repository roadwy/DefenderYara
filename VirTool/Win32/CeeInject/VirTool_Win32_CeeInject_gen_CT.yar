
rule VirTool_Win32_CeeInject_gen_CT{
	meta:
		description = "VirTool:Win32/CeeInject.gen!CT,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {00 6d 69 63 72 6f 73 6f 66 74 2e 63 6f 6d 00 00 00 2e 2e 00 00 } //1
		$a_01_1 = {4c 6f 61 64 52 65 73 6f 75 72 63 65 } //1 LoadResource
		$a_01_2 = {4e 74 55 6e 6d 61 70 56 69 65 77 4f 66 53 65 63 74 69 6f 6e } //1 NtUnmapViewOfSection
		$a_01_3 = {4e 74 57 72 69 74 65 56 69 72 74 75 61 6c 4d 65 6d 6f 72 79 } //1 NtWriteVirtualMemory
		$a_02_4 = {2a 04 1f 88 01 41 83 ee 01 75 90 01 01 5f 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_02_4  & 1)*1) >=5
 
}