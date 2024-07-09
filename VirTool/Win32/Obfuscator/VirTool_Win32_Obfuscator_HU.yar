
rule VirTool_Win32_Obfuscator_HU{
	meta:
		description = "VirTool:Win32/Obfuscator.HU,SIGNATURE_TYPE_PEHSTR_EXT,02 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {80 7a 78 6a 74 ?? 80 7a 47 89 74 ?? 80 7a 49 3b 74 ?? cc } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}