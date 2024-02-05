
rule VirTool_Win32_VBInject_AJN_bit{
	meta:
		description = "VirTool:Win32/VBInject.AJN!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {81 fa 41 41 41 41 0f 85 90 01 02 ff ff 90 0a 40 00 5e 90 0a 40 00 33 14 24 90 00 } //01 00 
		$a_03_1 = {8b 80 cc 10 00 00 90 02 30 6a 47 90 02 30 83 2c 24 07 90 02 30 68 02 10 00 00 90 02 30 83 2c 24 02 90 02 30 68 00 62 00 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}