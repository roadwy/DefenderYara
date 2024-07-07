
rule VirTool_Win32_VBInject_SW{
	meta:
		description = "VirTool:Win32/VBInject.SW,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {6a 6b ff d7 8b d0 8d 8d 80 fc ff ff ff d6 6a 65 ff d7 8b d0 8d 8d 7c fc ff ff ff d6 6a 72 ff d7 8b d0 8d 8d 78 fc ff ff ff d6 6a 6e ff d7 8b d0 8d 8d 74 fc ff ff ff d6 6a 65 ff d7 8b d0 8d 8d 70 fc ff ff ff d6 6a 6c ff d7 8b d0 8d 8d 6c fc } //1
		$a_01_1 = {6a 35 ff d3 8b d0 8d 8d c8 fe ff ff ff d6 6a 6e ff d3 8b d0 8d 8d c4 fe ff ff ff d6 6a 67 ff d3 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}