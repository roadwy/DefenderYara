
rule VirTool_Win32_VBInject_BAA_bit{
	meta:
		description = "VirTool:Win32/VBInject.BAA!bit,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {b8 ce e3 04 00 90 02 20 05 88 1c 3d 00 90 02 20 39 41 04 90 02 20 68 31 d2 15 00 90 02 20 58 90 02 20 05 1c 2e 3d 00 90 02 20 39 01 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}