
rule VirTool_Win32_Injector_gen_EV{
	meta:
		description = "VirTool:Win32/Injector.gen!EV,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {33 d2 8a 51 06 8b 85 90 01 04 03 85 90 01 04 33 c9 8a 08 83 c1 03 3b d1 0f 85 90 01 04 8b 95 90 01 04 03 95 90 01 04 33 c0 8a 42 04 90 00 } //2
		$a_03_1 = {6a 03 6a 00 6a 01 68 00 00 00 80 68 90 01 04 ff 15 90 01 04 89 85 90 01 04 6a 00 8b 85 90 01 04 50 ff 15 90 01 04 89 45 90 01 01 6a 01 8b 4d 90 01 01 81 c1 00 04 00 00 51 ff 15 90 01 04 83 c4 08 89 85 90 01 04 6a 00 90 00 } //1
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*1) >=3
 
}