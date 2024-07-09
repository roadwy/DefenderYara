
rule VirTool_Win32_CeeInject_gen_CZ{
	meta:
		description = "VirTool:Win32/CeeInject.gen!CZ,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8d 7e 34 57 83 c2 08 52 ?? ff 15 ?? ?? ?? ?? 8b 4e 28 03 0f } //1
		$a_01_1 = {0f b7 48 06 43 83 c6 28 3b d9 7c d8 eb 04 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}