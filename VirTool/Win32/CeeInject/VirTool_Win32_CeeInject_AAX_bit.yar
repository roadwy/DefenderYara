
rule VirTool_Win32_CeeInject_AAX_bit{
	meta:
		description = "VirTool:Win32/CeeInject.AAX!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {58 50 59 03 49 3c 81 c1 ?? ?? ?? ?? 89 0d ?? ?? ?? ?? ff 15 } //1
		$a_03_1 = {57 72 69 74 c7 05 ?? ?? ?? ?? 63 65 73 73 c7 05 ?? ?? ?? ?? 4d 65 6d 6f } //1
		$a_01_2 = {8b 0e f8 83 de fc f7 d9 8d 49 f1 c1 c9 09 d1 c1 31 d9 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}