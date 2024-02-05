
rule VirTool_Win32_VBInject_AIA_bit{
	meta:
		description = "VirTool:Win32/VBInject.AIA!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {b8 30 00 00 00 64 8b 00 8b 40 0c 8b 70 14 64 a1 30 00 00 00 8b 40 18 c7 00 00 00 00 00 03 30 } //01 00 
		$a_01_1 = {bb 52 8b ec 83 43 43 43 39 18 75 ec bb eb 0c 56 8d 43 39 58 04 } //00 00 
	condition:
		any of ($a_*)
 
}