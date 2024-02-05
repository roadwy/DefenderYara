
rule VirTool_Win32_CeeInject_ABO_bit{
	meta:
		description = "VirTool:Win32/CeeInject.ABO!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {0f be 02 89 45 90 01 01 e8 90 01 04 33 45 90 01 01 8b 4d 08 03 4d 90 01 01 88 01 90 00 } //01 00 
		$a_03_1 = {55 8b ec 56 e8 90 01 04 8b f0 0f af 35 90 01 04 e8 90 01 04 8d 44 06 01 a3 90 01 04 8b 35 90 01 04 c1 ee 90 01 01 e8 90 01 04 23 c6 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}