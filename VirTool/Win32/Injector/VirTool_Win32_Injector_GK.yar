
rule VirTool_Win32_Injector_GK{
	meta:
		description = "VirTool:Win32/Injector.GK,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {b8 c4 01 00 00 83 ec 04 50 6a 00 52 e8 } //1
		$a_03_1 = {8a 00 31 c8 88 84 1d 90 01 02 ff ff 90 00 } //1
		$a_03_2 = {89 d0 c1 e0 02 01 d0 8d 14 85 00 00 00 00 01 d0 8d 55 90 01 01 01 d0 01 c8 2d 90 01 02 00 00 88 18 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}