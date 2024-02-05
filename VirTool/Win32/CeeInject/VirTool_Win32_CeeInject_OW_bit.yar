
rule VirTool_Win32_CeeInject_OW_bit{
	meta:
		description = "VirTool:Win32/CeeInject.OW!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {2b f0 33 d6 03 ca 8b 15 90 01 04 03 95 90 01 04 88 0a 90 00 } //01 00 
		$a_01_1 = {55 8b ec 6a 04 68 00 10 00 00 e8 41 cd ff ff 50 6a 00 ff 15 04 70 42 00 a3 e8 ad 42 00 5d } //00 00 
	condition:
		any of ($a_*)
 
}