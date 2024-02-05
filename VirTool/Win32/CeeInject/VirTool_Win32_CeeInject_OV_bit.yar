
rule VirTool_Win32_CeeInject_OV_bit{
	meta:
		description = "VirTool:Win32/CeeInject.OV!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {7d 30 0f b7 05 90 01 04 33 45 90 01 01 35 90 01 04 0f b7 0d 90 01 04 33 4d 90 01 01 81 f1 90 01 04 8b 15 90 01 04 8a 80 90 01 04 88 04 0a eb be 90 00 } //01 00 
		$a_03_1 = {eb 46 0f b7 05 90 01 04 83 c0 90 01 01 8b 0d 90 01 04 03 4d 90 01 01 0f be 11 33 d0 a1 90 01 04 03 45 90 01 01 88 10 eb 22 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}