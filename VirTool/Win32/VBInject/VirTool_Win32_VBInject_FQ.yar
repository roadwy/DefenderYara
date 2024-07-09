
rule VirTool_Win32_VBInject_FQ{
	meta:
		description = "VirTool:Win32/VBInject.FQ,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {0f b6 08 8b 45 ?? 99 6a 05 5e f7 fe 83 c2 02 0f 80 ?? ?? 00 00 33 ca } //1
		$a_03_1 = {66 0f b6 08 8b 45 84 8b 55 ?? 66 33 0c 42 } //1
		$a_01_2 = {52 74 6c 4d 6f 76 65 4d 65 6d 6f 72 79 00 } //1 瑒䵬癯䵥浥牯y
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}