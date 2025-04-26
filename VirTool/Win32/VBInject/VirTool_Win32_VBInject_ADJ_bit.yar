
rule VirTool_Win32_VBInject_ADJ_bit{
	meta:
		description = "VirTool:Win32/VBInject.ADJ!bit,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {be 00 10 40 00 ad 83 f8 00 74 fa 81 38 55 8b ec 83 75 ?? bb eb 0c 56 8d 43 39 58 04 75 ?? 31 db 53 53 53 54 68 00 00 04 00 52 51 54 89 85 c0 00 00 00 ff d0 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}