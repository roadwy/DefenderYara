
rule VirTool_Win32_VBInject_PH_bit{
	meta:
		description = "VirTool:Win32/VBInject.PH!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {bd 18 00 00 00 90 02 20 64 8b 6d 00 90 02 20 8b 6d 30 90 02 20 e9 90 00 } //01 00 
		$a_03_1 = {85 c9 0f 85 90 02 20 41 90 02 20 ff 77 2c 90 02 20 31 0c 24 90 00 } //00 00 
		$a_00_2 = {5d } //04 00 
	condition:
		any of ($a_*)
 
}