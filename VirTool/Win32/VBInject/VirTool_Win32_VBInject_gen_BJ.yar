
rule VirTool_Win32_VBInject_gen_BJ{
	meta:
		description = "VirTool:Win32/VBInject.gen!BJ,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_03_0 = {a8 fe ff ff 03 ?? 9c fe ff ff 0f 80 ?? ?? ?? ?? 89 ?? 58 fe ff ff } //2
		$a_03_1 = {8b 56 6c 8b 46 78 [0-03] 03 d0 [0-06] 89 96 c8 02 00 00 } //2
		$a_03_2 = {8a 1c 10 03 cb 0f 80 ?? ?? ?? ?? 81 e1 ff 00 00 80 79 08 49 81 c9 00 ff ff ff 41 89 4d } //1
		$a_01_3 = {58 59 59 59 6a 04 } //1 奘奙Ѫ
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2+(#a_03_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}