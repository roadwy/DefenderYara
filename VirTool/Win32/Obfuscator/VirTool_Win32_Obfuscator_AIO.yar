
rule VirTool_Win32_Obfuscator_AIO{
	meta:
		description = "VirTool:Win32/Obfuscator.AIO,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {40 00 b9 c8 00 00 00 30 06 46 e2 fb 8d 05 30 ?? 40 00 ff e0 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}