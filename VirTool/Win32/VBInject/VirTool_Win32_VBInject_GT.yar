
rule VirTool_Win32_VBInject_GT{
	meta:
		description = "VirTool:Win32/VBInject.GT,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {6a 48 e8 ae e4 ff ff 8b d0 8d 8d ec fe ff ff e8 b3 e4 ff ff 6a 53 e8 9a e4 ff ff 8b d0 8d 8d e8 fe ff ff e8 9f e4 ff ff 6a 66 e8 86 e4 ff ff 8b d0 8d 8d e4 fe ff ff e8 8b e4 ff ff 6a 65 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}