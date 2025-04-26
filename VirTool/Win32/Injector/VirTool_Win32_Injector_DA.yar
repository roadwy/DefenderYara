
rule VirTool_Win32_Injector_DA{
	meta:
		description = "VirTool:Win32/Injector.DA,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_03_0 = {43 43 58 31 0f 85 ?? ?? ?? ?? 83 3d ?? ?? ?? ?? 01 0f 85 90 09 06 00 81 3d } //1
		$a_03_1 = {58 59 59 59 90 09 03 00 (00 00 b8|c7) } //1
		$a_03_2 = {80 7d ff e9 75 ?? 33 c0 40 eb 02 } //1
		$a_01_3 = {64 a1 30 00 00 00 83 c0 68 3e 8b 00 83 f8 70 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}