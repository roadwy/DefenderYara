
rule VirTool_Win32_VBInject_ACG_bit{
	meta:
		description = "VirTool:Win32/VBInject.ACG!bit,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {68 54 8b ec 83 5b 43 be 00 10 40 00 90 02 20 ad 90 02 10 83 f8 00 74 90 02 10 39 18 75 90 02 10 81 78 04 ec 0c 56 8d 90 00 } //01 00 
		$a_03_1 = {be 00 10 40 00 ad 83 f8 00 74 90 02 10 68 54 8b ec 83 5b 43 39 18 75 90 02 10 81 78 04 ec 0c 56 8d 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}