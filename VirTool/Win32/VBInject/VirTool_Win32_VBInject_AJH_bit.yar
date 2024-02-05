
rule VirTool_Win32_VBInject_AJH_bit{
	meta:
		description = "VirTool:Win32/VBInject.AJH!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {b9 41 41 41 41 90 02 30 46 90 02 30 8b 17 90 02 30 31 f2 90 02 30 75 90 00 } //01 00 
		$a_03_1 = {bb f4 cb 6c 00 90 02 30 81 c3 59 8e 23 00 90 02 30 48 90 02 30 39 18 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule VirTool_Win32_VBInject_AJH_bit_2{
	meta:
		description = "VirTool:Win32/VBInject.AJH!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {05 c0 10 00 00 90 09 20 00 75 90 09 20 00 39 18 90 02 20 00 48 90 00 } //01 00 
		$a_03_1 = {b9 41 41 41 41 90 02 30 46 90 02 30 ff 37 90 02 30 31 34 24 90 02 30 5a 90 02 30 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}