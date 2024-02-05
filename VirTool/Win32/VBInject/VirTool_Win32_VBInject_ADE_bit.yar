
rule VirTool_Win32_VBInject_ADE_bit{
	meta:
		description = "VirTool:Win32/VBInject.ADE!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {31 ff 81 cf 4c 00 53 00 eb 21 90 0a 30 00 8b 00 90 02 10 8b 58 28 90 00 } //01 00 
		$a_03_1 = {bb 83 ec 8b 54 90 02 30 43 39 18 75 90 01 01 c1 ee 00 81 78 04 ec 0c 56 8d 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}