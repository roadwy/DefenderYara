
rule VirTool_Win32_VBInject_ME{
	meta:
		description = "VirTool:Win32/VBInject.ME,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {81 c3 f8 00 00 00 8b 0e 0f 80 90 01 04 6b c0 28 0f 80 90 01 04 03 d8 90 00 } //01 00 
		$a_03_1 = {80 fb 09 76 13 66 33 c9 8a cb 66 83 e9 07 0f 80 90 01 04 ff d7 8a d8 8a 45 e0 3c 09 76 14 90 00 } //01 00 
		$a_01_2 = {c7 45 a8 e8 00 00 00 89 7d a0 } //00 00 
	condition:
		any of ($a_*)
 
}