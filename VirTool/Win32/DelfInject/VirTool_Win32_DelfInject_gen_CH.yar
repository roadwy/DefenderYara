
rule VirTool_Win32_DelfInject_gen_CH{
	meta:
		description = "VirTool:Win32/DelfInject.gen!CH,SIGNATURE_TYPE_PEHSTR_EXT,03 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {6a 40 68 00 30 00 00 8b 47 50 50 8b 47 34 50 8b 45 d0 50 } //1
		$a_03_1 = {33 c0 89 45 90 01 01 8b de 66 81 3b 4d 5a 0f 85 90 01 02 00 00 8b fe 03 7b 3c 81 3f 50 45 00 00 0f 85 90 01 02 00 00 8d 45 90 01 01 33 c9 ba 44 00 00 00 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}