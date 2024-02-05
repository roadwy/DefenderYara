
rule VirTool_Win32_CeeInject_UD_bit{
	meta:
		description = "VirTool:Win32/CeeInject.UD!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {2b d1 89 55 90 01 01 8b 45 90 01 01 8b 0c 85 90 01 04 33 0d 90 01 04 8b 55 90 01 01 8b 45 90 01 01 89 0c 90 90 90 00 } //01 00 
		$a_03_1 = {8b 04 8a 33 05 90 01 04 8b 4d 90 01 01 8b 55 90 01 01 89 04 8a 90 00 } //01 00 
		$a_03_2 = {83 c2 3e 52 a1 90 01 04 50 8b 4d 90 01 01 51 8b 15 90 01 04 52 ff 15 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}