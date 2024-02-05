
rule VirTool_Win32_CeeInject_AAH_bit{
	meta:
		description = "VirTool:Win32/CeeInject.AAH!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {69 c0 fd 43 03 00 05 90 01 04 a3 90 01 04 c1 e8 10 25 ff 7f 00 00 c3 90 00 } //01 00 
		$a_03_1 = {6a 00 ff 15 90 01 04 e8 90 01 04 30 04 3e 6a 00 90 00 } //01 00 
		$a_03_2 = {85 ff 75 3d 68 90 01 04 c7 05 90 01 04 6b 65 72 6e c6 05 90 01 04 65 88 1d 90 01 04 c7 05 90 01 04 33 32 2e 64 88 1d 90 01 04 88 1d 90 01 04 c6 05 90 01 04 00 ff d6 8b f8 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}