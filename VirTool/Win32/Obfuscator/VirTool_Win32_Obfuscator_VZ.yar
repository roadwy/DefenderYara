
rule VirTool_Win32_Obfuscator_VZ{
	meta:
		description = "VirTool:Win32/Obfuscator.VZ,SIGNATURE_TYPE_PEHSTR_EXT,02 00 01 00 01 00 00 "
		
	strings :
		$a_13_0 = {a1 30 00 00 00 8b 40 0c 8b 40 1c 8b 40 08 e8 04 00 00 00 90 01 04 59 ff 31 90 00 00 } //1
	condition:
		((#a_13_0  & 1)*1) >=1
 
}