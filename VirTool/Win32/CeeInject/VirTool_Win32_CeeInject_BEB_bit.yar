
rule VirTool_Win32_CeeInject_BEB_bit{
	meta:
		description = "VirTool:Win32/CeeInject.BEB!bit,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {ff 4d 08 ff 93 90 01 04 8b 4d 0c 03 c8 83 f8 00 72 14 83 f9 0a 76 0f 83 7d 08 00 76 09 50 ff 75 08 e8 d3 ff ff ff 3b c8 75 10 83 7d 08 00 76 0a 6a 64 ff 75 08 e8 bf ff ff ff 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}