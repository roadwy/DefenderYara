
rule VirTool_Win32_Obfuscator_AGJ{
	meta:
		description = "VirTool:Win32/Obfuscator.AGJ,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {60 8b 7d 08 8b 47 3c 8b 54 38 78 8b 44 38 7c 89 45 f4 03 d7 89 55 ?? 01 55 ?? 8b 4a 18 8b 5a 20 03 df 0b c9 } //1
		$a_03_1 = {8b 45 fc c1 c0 ?? 89 45 fc 8b 06 33 45 fc 89 06 83 ee 04 3b 75 08 73 e8 61 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}