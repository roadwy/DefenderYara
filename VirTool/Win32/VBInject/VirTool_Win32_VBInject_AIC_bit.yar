
rule VirTool_Win32_VBInject_AIC_bit{
	meta:
		description = "VirTool:Win32/VBInject.AIC!bit,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {b8 ca 5c 12 00 90 02 30 05 8c a3 2f 00 90 02 30 39 01 90 02 30 0f 90 02 30 83 e9 04 90 02 30 68 1e 28 23 00 90 02 30 58 90 02 30 05 2f d8 2f 00 90 02 30 8b 09 90 02 30 39 c1 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}