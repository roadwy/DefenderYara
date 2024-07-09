
rule VirTool_Win32_VBInject_gen_LC{
	meta:
		description = "VirTool:Win32/VBInject.gen!LC,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {c7 00 55 89 e5 eb 6a 04 58 6b c0 03 8b 0d ?? ?? ?? 00 c7 04 01 00 75 f6 c9 a1 ?? ?? ?? 00 c7 40 04 0c 31 37 83 6a 04 58 6b c0 06 8b 0d ?? ?? ?? 00 c7 04 01 ec 00 00 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}