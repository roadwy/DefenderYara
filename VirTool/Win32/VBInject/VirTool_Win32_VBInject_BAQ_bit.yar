
rule VirTool_Win32_VBInject_BAQ_bit{
	meta:
		description = "VirTool:Win32/VBInject.BAQ!bit,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b 06 83 c6 04 bb 54 8b ec 83 43 39 18 75 f1 bb eb 0c 56 8d 43 39 58 04 75 e6 31 db 53 53 53 54 68 00 00 04 00 52 51 54 ff d0 83 c4 1c } //00 00 
	condition:
		any of ($a_*)
 
}