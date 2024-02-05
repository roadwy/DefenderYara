
rule VirTool_Win32_VBInject_AJM_bit{
	meta:
		description = "VirTool:Win32/VBInject.AJM!bit,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {31 f6 81 ce 00 10 40 00 2b b5 c0 00 00 00 8b 06 83 c6 04 bb 53 8b ec 83 43 66 43 39 18 75 ef bb eb 0c 56 8d 43 39 58 04 75 e4 31 db 53 53 53 54 68 00 00 04 00 } //00 00 
	condition:
		any of ($a_*)
 
}