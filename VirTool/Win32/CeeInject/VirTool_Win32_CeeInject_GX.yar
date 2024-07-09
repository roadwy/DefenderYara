
rule VirTool_Win32_CeeInject_GX{
	meta:
		description = "VirTool:Win32/CeeInject.GX,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {89 e9 66 81 e9 ?? [80-ff] 0f 82 ?? ?? ?? ?? 87 ?? ?? 01 90 04 01 03 c[0-28] 68] ?? ?? ?? ?? 6a 00 68 00 00 10 00 2e ff 15 ?? ?? ?? ?? 85 c0 0f 85 [0-ff] 68 90 1b 06 6a 00 68 00 00 10 00 2e ff 15 90 1b 07 83 f8 00 0f 85 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}