
rule VirTool_Win32_Injector_gen_X{
	meta:
		description = "VirTool:Win32/Injector.gen!X,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {41 8a 4c 0c 14 32 0c 2f 88 0f 8b 8c 24 20 01 00 00 40 3b c1 7c 9e } //1
		$a_02_1 = {02 cb 88 88 90 01 04 8a 0d 90 01 04 02 d1 88 90 90 90 01 04 83 c0 02 3d e0 00 00 00 72 d4 90 00 } //1
		$a_02_2 = {8b 6c 24 14 33 db 66 39 5d 06 76 90 01 01 57 8b 7c 24 28 83 c7 08 8b 07 85 c0 74 90 01 01 33 d2 f7 f1 85 d2 8b 15 90 01 04 75 90 01 01 8b 07 eb 90 00 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_02_1  & 1)*1+(#a_02_2  & 1)*1) >=3
 
}