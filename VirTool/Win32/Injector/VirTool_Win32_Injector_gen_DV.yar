
rule VirTool_Win32_Injector_gen_DV{
	meta:
		description = "VirTool:Win32/Injector.gen!DV,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_01_0 = {8d 6c 24 44 0f bf 45 06 39 c3 0f } //1
		$a_03_1 = {6b ff 28 01 fb 89 9c 24 ?? ?? ?? ?? 8b 9c 24 ?? ?? ?? ?? 03 9c 24 } //1
		$a_01_2 = {56 56 d6 41 00 00 00 00 40 16 d4 40 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=2
 
}