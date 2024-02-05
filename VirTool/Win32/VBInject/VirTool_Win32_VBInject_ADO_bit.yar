
rule VirTool_Win32_VBInject_ADO_bit{
	meta:
		description = "VirTool:Win32/VBInject.ADO!bit,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {be 00 10 40 00 ad 83 f8 00 74 fa bb 53 8b ec 83 83 c3 02 39 18 75 ee bb ea 0c 56 8d 43 43 39 58 04 75 e2 31 db 53 53 53 54 ff 75 14 52 51 54 89 85 c0 00 00 00 ff d0 } //00 00 
	condition:
		any of ($a_*)
 
}