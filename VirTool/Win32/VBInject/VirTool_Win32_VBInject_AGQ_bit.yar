
rule VirTool_Win32_VBInject_AGQ_bit{
	meta:
		description = "VirTool:Win32/VBInject.AGQ!bit,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {68 56 f7 04 00 90 02 10 58 90 02 10 90 02 10 05 00 09 3d 00 90 02 10 39 41 04 75 90 02 10 68 8d 39 25 00 90 02 10 58 90 02 10 05 c0 c6 2d 00 90 02 10 39 01 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}