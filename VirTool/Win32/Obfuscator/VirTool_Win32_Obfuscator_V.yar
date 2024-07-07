
rule VirTool_Win32_Obfuscator_V{
	meta:
		description = "VirTool:Win32/Obfuscator.V,SIGNATURE_TYPE_PEHSTR_EXT,02 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 2c 08 2c 08 8b 45 45 90 8b 45 45 90 8b 45 45 90 8b 45 45 90 90 8b 45 45 e9 c9 f8 fe ff } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}