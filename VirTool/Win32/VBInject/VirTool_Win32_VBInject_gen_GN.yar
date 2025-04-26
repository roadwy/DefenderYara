
rule VirTool_Win32_VBInject_gen_GN{
	meta:
		description = "VirTool:Win32/VBInject.gen!GN,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {00 4e 74 57 72 69 74 65 56 69 72 74 75 61 6c 4d 65 6d 6f 72 79 00 } //1 一坴楲整楖瑲慵䵬浥牯y
		$a_01_1 = {4d 6f 64 75 6c 65 31 00 4d 6f 64 75 6c 65 32 00 4d 6f 64 75 6c 65 33 00 4d 6f 64 75 6c 65 34 00 4d 6f 64 75 6c 65 35 00 4d 6f 64 75 6c 65 36 00 } //1 潍畤敬1潍畤敬2潍畤敬3潍畤敬4潍畤敬5潍畤敬6
		$a_01_2 = {49 6e 66 6f 20 7a 75 20 6d 65 69 6e 65 72 20 41 6e 77 65 6e 64 75 6e 67 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}