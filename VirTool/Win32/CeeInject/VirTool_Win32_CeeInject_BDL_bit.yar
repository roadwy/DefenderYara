
rule VirTool_Win32_CeeInject_BDL_bit{
	meta:
		description = "VirTool:Win32/CeeInject.BDL!bit,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8d 45 f8 50 6a 40 68 23 52 00 00 8b 45 08 50 ff 55 f4 [0-10] 33 c0 89 45 f0 8b 45 f0 89 45 f8 8b 45 08 03 45 f8 8a 00 88 45 ef [0-10] 8a 45 ef 34 ?? 8b 55 08 03 55 f8 88 02 ff 45 f0 81 7d f0 ?? ?? ?? ?? 75 ?? 8b 45 08 05 94 05 00 00 89 45 fc ff 65 fc } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}