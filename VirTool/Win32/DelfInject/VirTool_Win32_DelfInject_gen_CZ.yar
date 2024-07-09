
rule VirTool_Win32_DelfInject_gen_CZ{
	meta:
		description = "VirTool:Win32/DelfInject.gen!CZ,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {07 00 01 00 90 09 06 00 [0-04] c7 } //1
		$a_03_1 = {6a 04 68 00 30 00 00 8b 85 ?? ?? ?? ?? 50 8b 85 ?? ?? ?? ?? 50 8b 85 ?? ?? ?? ?? 50 8b 45 ?? ff 50 } //1
		$a_03_2 = {c1 e0 03 8d 04 80 99 03 04 24 13 54 24 04 83 c4 08 8b 15 ?? ?? ?? ?? 03 d0 8d 85 ?? ?? ?? ?? b9 28 00 00 00 90 09 31 00 81 c7 f8 00 00 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}