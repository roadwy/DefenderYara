
rule VirTool_Win32_Injector_JR{
	meta:
		description = "VirTool:Win32/Injector.JR,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {68 73 15 00 00 68 84 05 00 00 e8 ?? ?? ?? ?? 83 c4 08 [0-06] 81 } //1
		$a_03_1 = {83 f8 50 75 ?? 8b c0 8d 15 ?? ?? ?? ?? 89 55 f8 81 6d f8 05 14 00 00 81 45 f8 8a 10 00 00 } //1
		$a_01_2 = {50 8b ff 8b c9 8b ff c3 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}