
rule VirTool_Win32_CeeInject_SR_bit{
	meta:
		description = "VirTool:Win32/CeeInject.SR!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {48 50 ff 75 90 01 01 ff 75 90 01 01 a1 90 01 04 8b 0d 90 01 04 ff d0 90 00 } //01 00 
		$a_01_1 = {8b 55 08 8b 02 03 45 fc 8b 4d 08 89 01 } //01 00 
		$a_03_2 = {8b ca 33 c1 8b d2 c7 45 fc 00 00 00 00 8b d2 01 45 fc 8b d2 8b 0d 90 01 04 8b 55 fc 89 11 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}