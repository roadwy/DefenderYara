
rule VirTool_Win32_VBInject_ADI_bit{
	meta:
		description = "VirTool:Win32/VBInject.ADI!bit,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {bb 5a 8b ec 83 66 83 eb 05 39 18 75 90 01 01 bb ef 0c 56 8d 4b 4b 4b 39 58 04 75 90 01 01 31 db 53 53 53 54 68 00 30 04 00 52 51 54 ff d0 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}