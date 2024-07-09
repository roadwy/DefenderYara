
rule VirTool_Win32_Obfuscator_AEB{
	meta:
		description = "VirTool:Win32/Obfuscator.AEB,SIGNATURE_TYPE_PEHSTR_EXT,64 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {85 c0 74 05 6a 00 ff 55 0c 68 ?? ?? ?? ?? 8b 4d 08 51 e8 ?? ?? ?? ?? 83 c4 08 85 c0 74 05 6a 00 ff 55 0c } //2
		$a_01_1 = {53 00 41 00 4d 00 50 00 4c 00 45 00 00 00 00 00 56 00 49 00 52 00 55 00 53 00 00 00 } //1
		$a_03_2 = {70 17 00 00 7d 07 6a 00 ff 55 ?? eb e7 90 09 0e 00 eb 09 8b 45 ?? 83 c0 01 89 45 ?? 81 7d } //1
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}