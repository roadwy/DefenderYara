
rule VirTool_Win32_VBInject_ADA_bit{
	meta:
		description = "VirTool:Win32/VBInject.ADA!bit,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {68 53 8b ec 83 90 02 10 5b 90 02 10 43 43 be 00 10 40 00 90 02 10 ad 90 02 10 83 f8 00 74 90 02 10 39 18 75 90 02 10 81 78 04 ec 0c 56 8d 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}