
rule VirTool_Win32_Obfuscator_RS{
	meta:
		description = "VirTool:Win32/Obfuscator.RS,SIGNATURE_TYPE_PEHSTR_EXT,02 00 01 00 01 00 00 "
		
	strings :
		$a_09_0 = {ff 95 64 fe ff ff 83 bd 48 fe ff ff 10 76 0c c7 85 48 fe ff ff 40 00 00 00 eb 0a c7 85 48 fe ff ff 04 00 00 00 61 60 } //1
	condition:
		((#a_09_0  & 1)*1) >=1
 
}