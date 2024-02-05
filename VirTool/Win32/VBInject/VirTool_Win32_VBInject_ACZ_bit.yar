
rule VirTool_Win32_VBInject_ACZ_bit{
	meta:
		description = "VirTool:Win32/VBInject.ACZ!bit,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {be 00 10 40 00 90 02 30 ad 90 02 30 74 90 02 30 bb 52 8b ec 83 90 02 30 83 c3 03 90 02 30 75 90 02 30 bb ea 0c 56 8d 90 02 30 83 c3 02 90 02 30 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}