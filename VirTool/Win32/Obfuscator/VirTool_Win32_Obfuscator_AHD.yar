
rule VirTool_Win32_Obfuscator_AHD{
	meta:
		description = "VirTool:Win32/Obfuscator.AHD,SIGNATURE_TYPE_PEHSTR_EXT,14 00 03 00 04 00 00 "
		
	strings :
		$a_03_0 = {bb 01 00 00 00 8b 45 fc 8a 44 18 ff e8 ?? ?? ?? ?? 33 c7 50 8d 45 fc e8 ?? ?? ?? ?? 5a 88 54 18 ff 43 4e 75 e0 } //1
		$a_03_1 = {db 75 ea 8d 05 90 09 18 00 bb ?? ?? ?? ?? b8 ?? ?? ?? ?? 8b cb ba ?? ?? 00 00 e8 ?? ?? ?? ?? 4b 85 } //1
		$a_03_2 = {8b 40 18 89 45 fc c6 45 ?? 47 c6 45 ?? 50 c6 45 ?? 41 33 c0 } //1
		$a_03_3 = {8a 19 3a 5d ?? 75 3b 8a 59 03 3a 5d ?? 75 33 8a 49 07 3a 4d ?? 75 2b } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1) >=3
 
}