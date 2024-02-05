
rule VirTool_Win32_CeeInject_GI{
	meta:
		description = "VirTool:Win32/CeeInject.GI,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 04 00 "
		
	strings :
		$a_01_0 = {c7 00 63 61 74 73 05 04 00 00 00 c7 00 72 76 2e 64 05 04 00 00 00 c7 00 6c 6c 00 00 05 04 00 00 00 } //01 00 
		$a_01_1 = {ff 10 85 c0 0f 85 25 00 00 00 0f 85 1f 00 00 00 0f 85 19 00 00 00 0f 85 13 00 00 00 0f 85 0d 00 00 00 } //01 00 
		$a_01_2 = {60 8b da 50 4b 03 de 88 03 58 61 } //00 00 
	condition:
		any of ($a_*)
 
}