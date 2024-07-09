
rule VirTool_Win32_CeeInject_AMT_bit{
	meta:
		description = "VirTool:Win32/CeeInject.AMT!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {56 68 00 30 00 00 50 53 ff 15 ?? ?? ?? 00 89 85 ?? ?? ?? ff } //1
		$a_01_1 = {68 00 de 44 00 50 ff d7 } //1
		$a_03_2 = {8a c3 32 85 [0-30] 88 84 ?? ?? ?? ?? ff } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}