
rule VirTool_Win32_Obfuscator_OI{
	meta:
		description = "VirTool:Win32/Obfuscator.OI,SIGNATURE_TYPE_PEHSTR_EXT,02 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b7 43 14 ff 73 50 8d 7c 18 18 6a 00 ff 15 90 01 04 89 45 90 01 01 85 c0 0f 84 90 01 04 ff 73 54 56 50 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}