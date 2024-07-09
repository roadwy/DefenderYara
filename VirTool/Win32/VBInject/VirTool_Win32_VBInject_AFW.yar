
rule VirTool_Win32_VBInject_AFW{
	meta:
		description = "VirTool:Win32/VBInject.AFW,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {31 db 90 43 e0 fc ff d3 } //1
		$a_03_1 = {8b 84 24 20 01 00 00 [0-0f] 5d [0-0f] ff e0 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}