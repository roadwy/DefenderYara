
rule VirTool_Win32_VBInject_OY{
	meta:
		description = "VirTool:Win32/VBInject.OY,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {50 56 6a ff ff d3 8b f0 8d 55 ?? f7 de 1b f6 8d 45 ?? 52 46 50 6a 02 } //1
		$a_03_1 = {85 f6 74 47 8b 7d 0c 8b 07 50 8d 4d c4 51 ff d3 50 56 ff 15 ?? ?? ?? ?? 8b f0 8b 55 c4 52 57 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}