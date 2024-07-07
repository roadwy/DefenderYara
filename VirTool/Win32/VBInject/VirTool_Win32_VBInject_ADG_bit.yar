
rule VirTool_Win32_VBInject_ADG_bit{
	meta:
		description = "VirTool:Win32/VBInject.ADG!bit,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {be 00 10 40 00 ad 83 f8 00 74 fa 81 38 55 8b ec 83 75 f2 bb eb 0c 56 8d 43 39 58 04 75 e7 31 db 53 53 53 54 6a 00 c7 04 24 00 00 04 00 52 51 54 89 85 c0 00 00 00 ff d0 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}