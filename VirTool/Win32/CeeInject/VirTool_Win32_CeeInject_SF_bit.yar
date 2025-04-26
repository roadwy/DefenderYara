
rule VirTool_Win32_CeeInject_SF_bit{
	meta:
		description = "VirTool:Win32/CeeInject.SF!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {6a 00 ff d7 8a 96 ?? ?? ?? ?? a1 ?? ?? ?? ?? 88 14 30 46 3b 75 fc 72 e8 } //1
		$a_01_1 = {8b c7 c1 e8 05 03 45 f0 8b cf c1 e1 04 03 4d ec 8d 14 3b 33 c1 33 c2 2b f0 8b c6 c1 e8 05 03 45 e8 8b ce c1 e1 04 03 4d e4 8d 14 33 33 c1 33 c2 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}