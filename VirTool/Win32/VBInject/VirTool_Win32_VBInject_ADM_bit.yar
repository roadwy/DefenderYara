
rule VirTool_Win32_VBInject_ADM_bit{
	meta:
		description = "VirTool:Win32/VBInject.ADM!bit,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {be 00 10 40 00 31 c0 0b 06 83 c6 04 bb 51 8b ec 83 83 c3 04 39 18 75 ed bb e9 0c 56 8d 83 c3 03 39 58 04 75 e0 31 db 53 53 53 54 68 00 00 01 00 81 04 24 00 00 03 00 52 51 54 89 85 c0 00 00 00 ff d0 } //00 00 
	condition:
		any of ($a_*)
 
}