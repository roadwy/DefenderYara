
rule VirTool_Win32_VBInject_PF_bit{
	meta:
		description = "VirTool:Win32/VBInject.PF!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {b8 30 00 00 00 90 02 30 64 ff 30 90 02 30 58 90 02 30 8b 40 0c 90 02 30 eb 90 00 } //01 00 
		$a_03_1 = {85 c9 0f 85 90 02 30 41 90 02 30 8b 53 2c 90 02 30 31 ca 90 02 30 85 d2 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}