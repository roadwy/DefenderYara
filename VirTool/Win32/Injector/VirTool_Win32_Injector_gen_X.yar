
rule VirTool_Win32_Injector_gen_X{
	meta:
		description = "VirTool:Win32/Injector.gen!X,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {41 8a 4c 0c 14 32 0c 2f 88 0f 8b 8c 24 20 01 00 00 40 3b c1 7c 9e } //1
		$a_02_1 = {02 cb 88 88 ?? ?? ?? ?? 8a 0d ?? ?? ?? ?? 02 d1 88 90 90 ?? ?? ?? ?? 83 c0 02 3d e0 00 00 00 72 d4 } //1
		$a_02_2 = {8b 6c 24 14 33 db 66 39 5d 06 76 ?? 57 8b 7c 24 28 83 c7 08 8b 07 85 c0 74 ?? 33 d2 f7 f1 85 d2 8b 15 ?? ?? ?? ?? 75 ?? 8b 07 eb } //1
	condition:
		((#a_00_0  & 1)*1+(#a_02_1  & 1)*1+(#a_02_2  & 1)*1) >=3
 
}