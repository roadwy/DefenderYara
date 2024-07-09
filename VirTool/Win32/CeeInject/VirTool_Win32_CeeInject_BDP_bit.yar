
rule VirTool_Win32_CeeInject_BDP_bit{
	meta:
		description = "VirTool:Win32/CeeInject.BDP!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 01 00 02 00 00 "
		
	strings :
		$a_03_0 = {55 8b ec 51 89 45 fc 8b 5d fc [0-10] 81 c3 33 36 00 00 [0-10] ff e3 90 0a 20 00 34 ?? 88 02 } //1
		$a_03_1 = {54 6a 40 68 ?? ?? ?? ?? 57 e8 ?? ?? ?? ff 90 0a 20 00 b8 ?? ?? ?? ?? e8 ?? ?? ?? ff } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=1
 
}