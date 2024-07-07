
rule VirTool_Win32_VBInject_gen_CA{
	meta:
		description = "VirTool:Win32/VBInject.gen!CA,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {43 72 65 61 74 65 50 72 6f 63 65 73 73 41 00 90 01 39 57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 00 90 00 } //1
		$a_03_1 = {8b 48 0c 2b 48 14 8b 85 90 01 02 ff ff 03 4d c0 51 8b 4d b8 03 c8 51 ff b5 90 01 02 ff ff e8 90 01 04 e8 90 01 04 8d 85 90 01 02 ff ff 50 e8 90 01 04 6a 01 58 01 45 e8 e9 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}