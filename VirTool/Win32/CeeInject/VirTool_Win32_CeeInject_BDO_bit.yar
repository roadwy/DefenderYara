
rule VirTool_Win32_CeeInject_BDO_bit{
	meta:
		description = "VirTool:Win32/CeeInject.BDO!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 01 00 03 00 00 "
		
	strings :
		$a_03_0 = {55 8b ec 51 89 45 fc 8b 5d fc [0-10] 81 c3 [0-10] 53 90 0a 20 00 34 ?? 88 02 } //1
		$a_03_1 = {55 8b ec 51 89 45 fc 8b 4d fc [0-10] 81 c1 [0-10] 51 [0-10] c3 90 0a 30 00 34 ?? 88 02 } //1
		$a_03_2 = {54 6a 40 68 ?? ?? ?? ?? 57 e8 ?? ?? ?? ff 90 0a 20 00 b8 ?? ?? ?? ?? e8 ?? ?? ?? ff } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=1
 
}