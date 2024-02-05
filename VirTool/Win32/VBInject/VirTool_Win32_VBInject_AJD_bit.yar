
rule VirTool_Win32_VBInject_AJD_bit{
	meta:
		description = "VirTool:Win32/VBInject.AJD!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {81 fa 41 41 41 41 90 0a 30 00 5a 90 0a 30 00 31 34 24 90 00 } //01 00 
		$a_03_1 = {05 cc 10 00 00 90 02 30 8b 00 90 02 30 6a 47 90 02 30 83 2c 24 07 90 02 30 68 02 10 00 00 90 02 30 83 2c 24 02 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}