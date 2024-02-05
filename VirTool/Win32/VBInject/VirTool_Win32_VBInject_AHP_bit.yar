
rule VirTool_Win32_VBInject_AHP_bit{
	meta:
		description = "VirTool:Win32/VBInject.AHP!bit,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {b8 30 00 00 00 90 02 20 64 ff 30 90 02 20 58 eb 90 02 20 8b 40 0c 90 02 20 8b 40 14 90 02 20 8b 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}