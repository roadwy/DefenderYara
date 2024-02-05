
rule VirTool_Win32_VBInject_AJE_bit{
	meta:
		description = "VirTool:Win32/VBInject.AJE!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {bb f4 cb 6c 00 90 02 30 81 c3 59 8e 23 00 90 02 30 48 90 02 30 39 18 90 00 } //01 00 
		$a_03_1 = {b9 41 41 41 41 90 02 30 46 90 02 30 8b 17 90 02 30 56 90 02 30 33 14 24 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}