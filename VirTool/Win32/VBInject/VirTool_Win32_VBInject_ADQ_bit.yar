
rule VirTool_Win32_VBInject_ADQ_bit{
	meta:
		description = "VirTool:Win32/VBInject.ADQ!bit,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {ad 85 c0 74 fb 03 04 24 bb 54 8b ec 83 43 39 18 75 ee 81 78 04 ec 0c 56 8d 75 } //00 00 
	condition:
		any of ($a_*)
 
}