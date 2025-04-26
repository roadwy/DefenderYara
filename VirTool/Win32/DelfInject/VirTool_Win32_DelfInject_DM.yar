
rule VirTool_Win32_DelfInject_DM{
	meta:
		description = "VirTool:Win32/DelfInject.DM,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {6a 04 68 00 30 00 00 68 00 40 06 00 6a 00 e8 ?? ?? ?? ff 89 45 f8 [0-30] 8d 45 f4 50 6a 00 68 e8 03 00 00 68 ?? ?? 40 00 6a 00 6a 00 e8 ?? ?? ?? ff } //1
		$a_03_1 = {56 89 c0 5e 4b 75 f9 90 09 05 00 bb } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}