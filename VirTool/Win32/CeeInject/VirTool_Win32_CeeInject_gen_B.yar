
rule VirTool_Win32_CeeInject_gen_B{
	meta:
		description = "VirTool:Win32/CeeInject.gen!B,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_00_0 = {46 69 6e 64 52 65 73 6f 75 72 63 65 41 } //1 FindResourceA
		$a_00_1 = {4c 6f 61 64 52 65 73 6f 75 72 63 65 } //1 LoadResource
		$a_00_2 = {43 72 65 61 74 65 50 72 6f 63 65 73 73 41 } //1 CreateProcessA
		$a_01_3 = {57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //1 WriteProcessMemory
		$a_03_4 = {ff 74 24 0c 8d 56 fc e8 90 01 04 8b 46 f4 31 02 8b 46 f8 31 06 83 ee 08 4b 59 75 e3 90 00 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_01_3  & 1)*1+(#a_03_4  & 1)*1) >=5
 
}