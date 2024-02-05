
rule VirTool_Win32_VBInject_GW{
	meta:
		description = "VirTool:Win32/VBInject.GW,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 07 00 07 00 00 05 00 "
		
	strings :
		$a_03_0 = {8b d0 8d 8d 5c ff ff ff ff 15 90 01 04 50 6a 01 6a ff 6a 20 ff 15 90 00 } //05 00 
		$a_03_1 = {c7 45 fc 0a 00 00 00 ba 90 01 04 8d 4d ac ff 15 90 01 04 c7 45 fc 0b 00 00 00 8d 45 88 89 85 20 ff ff ff c7 85 18 ff ff ff 08 40 00 00 90 00 } //01 00 
		$a_00_2 = {2e 00 53 00 63 00 72 00 00 00 } //01 00 
		$a_00_3 = {4d 00 4c 00 49 00 38 00 4c 00 00 00 } //01 00 
		$a_00_4 = {42 00 4b 00 4e 00 49 00 49 00 00 00 } //01 00 
		$a_00_5 = {49 00 45 00 48 00 30 00 31 00 00 00 } //01 00 
		$a_00_6 = {42 00 43 00 49 00 31 00 45 00 00 00 } //00 00 
	condition:
		any of ($a_*)
 
}