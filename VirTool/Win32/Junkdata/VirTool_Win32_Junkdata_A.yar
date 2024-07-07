
rule VirTool_Win32_Junkdata_A{
	meta:
		description = "VirTool:Win32/Junkdata.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_03_0 = {99 b9 ff 00 00 00 f7 f9 83 c7 01 3b 90 01 01 88 54 37 ff 7c e8 90 00 } //1
		$a_03_1 = {80 04 30 ff 83 c0 01 3b 90 01 01 7c f5 90 00 } //1
		$a_03_2 = {b9 1f 00 00 00 f7 f1 85 d2 0f 85 90 01 02 00 00 8b 4c 24 90 01 01 8b d1 83 e2 0f 80 fa 08 74 90 00 } //1
		$a_00_3 = {2d 64 20 00 2d 73 20 00 6d 64 35 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_00_3  & 1)*1) >=3
 
}