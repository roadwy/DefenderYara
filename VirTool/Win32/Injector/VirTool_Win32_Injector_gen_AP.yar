
rule VirTool_Win32_Injector_gen_AP{
	meta:
		description = "VirTool:Win32/Injector.gen!AP,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {64 8b 1d 30 00 00 00 [0-20] 8b 5b 0c } //1
		$a_03_1 = {83 c0 08 50 ff (75 ?? b5 ??|?? ?? ?? ff) 15 ?? ?? ?? ?? [0-20] 90 17 08 01 01 01 01 01 01 02 05 50 51 52 53 56 57 6a 00 68 00 00 00 00 ff 90 04 01 06 70 71 72 73 76 77 50 ff (75 ?? b5 ??|?? ?? ?? ff) (75 ?? b5 ??|?? ?? ?? ff) (75 ?? b5 ??|?? ?? ?? ff) 15 90 1b 01 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}