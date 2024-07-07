
rule VirTool_Win32_VBInject_UI{
	meta:
		description = "VirTool:Win32/VBInject.UI,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {4d 00 61 00 72 00 76 00 65 00 6c 00 5c 00 57 00 6f 00 6c 00 76 00 65 00 72 00 69 00 6e 00 65 00 5c 00 50 00 72 00 6f 00 6a 00 65 00 6b 00 74 00 31 00 2e 00 76 00 62 00 70 00 } //1 Marvel\Wolverine\Projekt1.vbp
		$a_01_1 = {4d 00 61 00 72 00 69 00 6f 00 42 00 72 00 6f 00 73 00 73 00 4d 00 61 00 72 00 69 00 6f 00 42 00 72 00 6f 00 73 00 73 00 4d 00 61 00 72 00 69 00 6f 00 42 00 72 00 6f 00 73 00 73 00 } //1 MarioBrossMarioBrossMarioBross
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}