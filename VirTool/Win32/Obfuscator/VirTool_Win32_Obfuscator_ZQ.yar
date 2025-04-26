
rule VirTool_Win32_Obfuscator_ZQ{
	meta:
		description = "VirTool:Win32/Obfuscator.ZQ,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {20 00 89 45 fc d1 e6 89 45 fc ff 16 90 09 03 00 be } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}