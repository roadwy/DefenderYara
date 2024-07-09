
rule VirTool_Win32_CeeInject_BDR_bit{
	meta:
		description = "VirTool:Win32/CeeInject.BDR!bit,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_03_0 = {55 8b ec 51 89 45 fc 8b 5d fc 68 ?? ?? ?? ?? 01 1c 24 c3 90 0a 30 00 8a 45 08 59 [0-10] 30 01 [0-10] 5d c2 08 00 } //1
		$a_03_1 = {55 8b ec 51 89 45 fc 8b 5d fc 68 ?? ?? ?? ?? 01 1c 24 c3 90 0a 40 00 8a 45 08 [0-10] 5b 30 03 [0-10] 5d c2 08 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=1
 
}