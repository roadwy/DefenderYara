
rule VirTool_Win32_VBInject_gen_HL{
	meta:
		description = "VirTool:Win32/VBInject.gen!HL,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {6a 45 50 e8 90 01 04 8d 85 90 01 02 ff ff 6a 4c 50 e8 90 01 04 8d 85 90 01 02 ff ff 6a 33 50 e8 90 01 04 8d 85 90 01 02 ff ff 6a 32 90 00 } //1
		$a_03_1 = {66 b9 e8 00 e8 90 01 04 8b 4d 90 01 01 03 8d 90 01 02 ff ff 88 01 8b 45 90 01 01 83 c0 01 90 00 } //1
		$a_03_2 = {6a 74 50 e8 90 01 04 8d 85 90 01 02 ff ff 6a 65 50 e8 90 01 04 8d 85 90 01 02 ff ff 6a 56 50 e8 90 01 04 8d 85 90 01 02 ff ff 6a 69 50 e8 90 01 04 8d 85 90 01 02 ff ff 6a 72 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}