
rule VirTool_Win32_Obfuscator_OS_MTB{
	meta:
		description = "VirTool:Win32/Obfuscator.OS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {03 84 bd e4 fb ff ff 25 ff 00 00 80 79 07 48 0d 00 ff ff ff 40 90 02 05 8a 84 85 e4 fb ff ff 32 45 ef 8b 4d f0 88 01 90 02 04 42 ff 4d e4 0f 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}