
rule VirTool_Win32_Obfuscator_AQX{
	meta:
		description = "VirTool:Win32/Obfuscator.AQX,SIGNATURE_TYPE_PEHSTR_EXT,06 00 01 00 03 00 00 "
		
	strings :
		$a_03_0 = {eb 07 8b 45 ?? 40 89 45 ?? 8b 45 ?? 3b 45 ?? 73 18 8b 45 ?? 03 45 ?? 0f b6 00 05 ?? 00 00 00 8b 4d ?? 03 4d ?? 88 01 eb d9 [0-18] ff 75 ?? 83 7d ?? 00 76 03 ff 55 90 1b 07 33 c0 8b 8d ?? ?? ff ff e8 } //1
		$a_03_1 = {eb 09 8b 4d ?? 83 c1 01 89 4d ?? 8b 55 ?? 3b 55 ?? 73 1a 8b 45 ?? 03 45 ?? 33 c9 8a 08 81 c1 ?? 00 00 00 8b 55 ?? 03 55 ?? 88 0a eb d5 ff 75 ?? 53 53 c3 } //1
		$a_03_2 = {8b 4d fc ff 55 fc eb [0-20] c7 45 ?? 00 00 00 00 eb 09 8b 4d ?? 83 c1 01 89 4d ?? 83 7d ?? ?? 7d [0-18] 8a 15 ?? ?? ?? ?? 80 ea 01 88 15 ?? ?? ?? ?? eb [d8-e8] } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=1
 
}