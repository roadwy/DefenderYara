
rule VirTool_Win32_DelfInject_gen_BC{
	meta:
		description = "VirTool:Win32/DelfInject.gen!BC,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_10_0 = {53 65 74 54 68 72 65 61 64 43 6f 6e 74 65 78 74 00 } //1
		$a_10_1 = {57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 00 } //1
		$a_10_2 = {52 74 6c 44 65 63 6f 6d 70 72 65 73 73 42 75 66 66 65 72 } //1 RtlDecompressBuffer
		$a_03_3 = {03 45 fc 50 8b 45 e8 8d 04 80 8b 55 dc 8b 44 c2 0c 03 45 f4 50 8b 45 c8 50 ff 15 90 01 02 40 00 ff 45 e8 ff 4d d8 75 90 00 } //1
		$a_03_4 = {3c e8 0f 84 90 01 02 00 00 e8 90 01 02 ff ff 3c ff 0f 84 90 00 } //1
	condition:
		((#a_10_0  & 1)*1+(#a_10_1  & 1)*1+(#a_10_2  & 1)*1+(#a_03_3  & 1)*1+(#a_03_4  & 1)*1) >=5
 
}