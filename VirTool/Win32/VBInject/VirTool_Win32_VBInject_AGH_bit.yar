
rule VirTool_Win32_VBInject_AGH_bit{
	meta:
		description = "VirTool:Win32/VBInject.AGH!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {c7 01 55 89 e5 e8 8b 4d 90 01 01 c7 41 04 90 01 02 00 00 8b 4d 90 01 01 c7 81 90 01 02 00 00 90 01 04 8b 4d 90 01 01 c7 81 90 01 02 00 00 90 01 04 8b 4d 90 01 01 c7 81 90 01 02 00 00 90 01 04 8b 4d 90 01 01 c7 81 90 01 02 00 00 90 01 04 8b 4d 90 01 01 c7 81 90 01 02 00 00 90 01 04 8b 4d 90 00 } //02 00 
		$a_03_1 = {31 37 83 c7 8b 45 90 01 01 c7 80 90 01 02 00 00 04 85 c0 75 8b 4d 90 01 01 c7 41 90 01 05 8b 45 90 01 01 c7 40 90 01 05 8b 4d 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}