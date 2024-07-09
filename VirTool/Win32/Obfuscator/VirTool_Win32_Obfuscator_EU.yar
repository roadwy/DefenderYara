
rule VirTool_Win32_Obfuscator_EU{
	meta:
		description = "VirTool:Win32/Obfuscator.EU,SIGNATURE_TYPE_PEHSTR_EXT,04 00 01 00 03 00 00 "
		
	strings :
		$a_07_0 = {68 00 30 40 00 ff 15 ?? ?? 40 00 90 09 0b 00 8d 45 ?? 50 6a 40 68 } //1
		$a_07_1 = {68 00 30 00 10 ff 15 ?? ?? 00 10 90 09 0b 00 8d 45 ?? 50 6a 40 68 } //1
		$a_07_2 = {68 00 30 14 13 ff 15 ?? ?? 14 13 90 09 0b 00 8d 45 ?? 50 6a 40 68 } //1
	condition:
		((#a_07_0  & 1)*1+(#a_07_1  & 1)*1+(#a_07_2  & 1)*1) >=1
 
}