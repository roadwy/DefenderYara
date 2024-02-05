
rule VirTool_Win32_VBInject_PG_bit{
	meta:
		description = "VirTool:Win32/VBInject.PG!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {bd 18 00 00 00 90 02 20 64 8b 6d 00 90 02 20 8b 6d 30 90 02 20 e9 90 00 } //01 00 
		$a_03_1 = {58 02 45 02 90 02 20 ff e0 90 00 } //01 00 
		$a_03_2 = {85 c9 0f 85 90 02 20 41 90 02 20 8b 57 2c 90 02 20 31 ca 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}