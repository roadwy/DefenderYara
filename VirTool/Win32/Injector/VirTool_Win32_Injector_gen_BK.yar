
rule VirTool_Win32_Injector_gen_BK{
	meta:
		description = "VirTool:Win32/Injector.gen!BK,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {33 d2 b9 ff 44 88 ff f7 f1 8d 94 3a 24 12 00 00 81 fa 24 12 00 00 } //1
		$a_02_1 = {0f b6 47 04 83 c7 04 (35|83) [0-04] 50 56 68 ?? ?? ?? 00 68 00 01 00 00 56 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}