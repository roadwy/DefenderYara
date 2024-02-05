
rule VirTool_Win32_VBInject_ACN_bit{
	meta:
		description = "VirTool:Win32/VBInject.ACN!bit,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {bb 59 8b ec 83 90 02 30 4b 90 02 30 4b 90 02 30 4b 90 02 30 4b 90 02 30 39 18 75 90 02 30 bb ef 0c 56 8d 90 02 30 4b 90 02 30 4b 90 02 30 4b 90 02 30 39 58 04 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}