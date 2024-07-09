
rule VirTool_Win32_CeeInject_gen_IW{
	meta:
		description = "VirTool:Win32/CeeInject.gen!IW,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {80 0f a2 3d 00 00 00 80 90 09 04 00 b8 00 00 00 } //1
		$a_01_1 = {83 c2 41 88 10 39 f0 75 e8 } //1
		$a_01_2 = {8a 04 11 30 04 37 46 } //1
		$a_01_3 = {00 52 65 73 75 6d 65 54 68 72 65 61 64 00 } //1 刀獥浵呥牨慥d
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}