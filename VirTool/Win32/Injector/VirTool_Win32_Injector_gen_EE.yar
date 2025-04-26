
rule VirTool_Win32_Injector_gen_EE{
	meta:
		description = "VirTool:Win32/Injector.gen!EE,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 03 00 00 "
		
	strings :
		$a_03_0 = {74 00 66 c7 45 (f0|f4) 2e 00 8b (|) 41 43 28 90 09 0d 00 66 c7 45 (|) ee f2 } //10
		$a_03_1 = {74 08 8d 85 ?? ?? ff ff ff d0 } //1
		$a_03_2 = {83 c0 01 89 45 ?? 81 7d 90 1b 00 80 0f 00 00 0f 85 ?? ?? ff ff [0-60] ff (55 ?? 95 ??|?? ?? ?? 33) c0 } //1
	condition:
		((#a_03_0  & 1)*10+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=1
 
}