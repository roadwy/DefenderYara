
rule VirTool_Win32_Obfuscator_GTK{
	meta:
		description = "VirTool:Win32/Obfuscator.GTK,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {53 89 e3 81 ec 80 00 00 00 89 e6 46 89 f7 90 02 08 6a 01 e8 90 01 02 ff ff 83 c4 04 c3 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}