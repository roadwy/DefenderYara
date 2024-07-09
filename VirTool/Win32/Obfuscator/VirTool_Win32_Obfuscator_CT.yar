
rule VirTool_Win32_Obfuscator_CT{
	meta:
		description = "VirTool:Win32/Obfuscator.CT,SIGNATURE_TYPE_PEHSTR_EXT,02 00 01 00 02 00 00 "
		
	strings :
		$a_07_0 = {c3 75 04 87 ?? ff ?? ?? eb f4 90 09 04 00 eb 0a 80 } //1
		$a_07_1 = {c3 75 04 89 ?? ff 90 09 04 00 eb 0a 80 } //1
	condition:
		((#a_07_0  & 1)*1+(#a_07_1  & 1)*1) >=1
 
}