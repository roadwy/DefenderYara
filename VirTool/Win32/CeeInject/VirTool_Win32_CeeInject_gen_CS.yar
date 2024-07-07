
rule VirTool_Win32_CeeInject_gen_CS{
	meta:
		description = "VirTool:Win32/CeeInject.gen!CS,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {43 72 65 61 74 65 50 72 6f 63 65 73 73 41 00 00 52 65 73 75 6d 65 54 68 72 65 61 64 00 00 00 00 56 69 72 74 75 61 6c 41 6c 6c 6f 63 00 00 00 00 } //1
		$a_01_1 = {4e 74 55 6e 6d 61 70 56 69 65 77 4f 66 53 65 63 74 69 6f 6e 00 00 00 00 57 72 69 74 65 50 72 6f 63 65 73 73 00 00 00 00 } //1
		$a_01_2 = {4c 6f 61 64 4c 69 62 72 61 72 79 41 00 } //1
		$a_00_3 = {81 c9 00 ff ff ff 41 8b 45 08 03 85 fc fb ff ff 0f b6 10 33 94 8d 00 fc ff ff 8b 45 08 03 85 fc fb ff ff 88 10 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}