
rule VirTool_Win32_CeeInject_SG_bit{
	meta:
		description = "VirTool:Win32/CeeInject.SG!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {83 f0 40 83 f0 06 50 68 90 01 04 68 90 01 04 6a 00 8b 4d 90 01 01 ff 91 90 01 04 50 8b 55 90 01 01 ff 92 90 00 } //01 00 
		$a_03_1 = {03 d1 81 e2 90 01 04 79 08 4a 81 ca 90 01 04 42 8b 4d 90 01 01 0f b6 94 11 90 01 04 33 c2 8b 4d 90 01 01 8b 91 90 01 04 8b 4d 90 01 01 88 04 0a e9 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}