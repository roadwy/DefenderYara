
rule VirTool_Win32_CeeInject_AAL_bit{
	meta:
		description = "VirTool:Win32/CeeInject.AAL!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {65 33 32 46 c7 05 90 01 04 69 72 73 74 66 c7 90 01 04 00 57 00 c7 05 90 01 04 4d 6f 64 75 c6 05 90 01 04 6c ff d6 90 00 } //01 00 
		$a_03_1 = {73 25 8b 45 90 01 01 89 85 90 01 04 8b 45 90 01 01 03 85 90 01 04 8b 4d 90 01 01 03 8d 90 01 04 8a 89 90 01 04 88 08 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}