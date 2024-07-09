
rule VirTool_Win32_CeeInject_BDQ_bit{
	meta:
		description = "VirTool:Win32/CeeInject.BDQ!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 01 00 02 00 00 "
		
	strings :
		$a_03_0 = {8d 45 f8 50 6a 40 68 ?? ?? ?? ?? 56 e8 ?? ?? ?? ff 90 0a 80 00 b8 ?? ?? ?? ?? e8 ?? ?? ?? ff 8b f0 } //1
		$a_03_1 = {55 8b ec 51 89 45 fc 8b 75 fc [0-10] 81 c6 [0-10] ff d6 90 0a 30 00 34 ?? 88 02 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=1
 
}