
rule VirTool_Win32_VBInject_AFW{
	meta:
		description = "VirTool:Win32/VBInject.AFW,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {31 db 90 43 e0 fc ff d3 } //01 00 
		$a_03_1 = {8b 84 24 20 01 00 00 90 02 0f 5d 90 02 0f ff e0 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}