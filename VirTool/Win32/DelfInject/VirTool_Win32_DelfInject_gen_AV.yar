
rule VirTool_Win32_DelfInject_gen_AV{
	meta:
		description = "VirTool:Win32/DelfInject.gen!AV,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {b1 ff 2a 08 88 08 40 4a 75 f6 c3 } //1
		$a_01_1 = {0f b7 52 14 03 c2 89 45 e8 8b 45 fc 0f b7 78 06 4f 85 ff 7c 6e } //1
		$a_03_2 = {69 70 74 6f 72 54 00 90 09 04 00 06 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}