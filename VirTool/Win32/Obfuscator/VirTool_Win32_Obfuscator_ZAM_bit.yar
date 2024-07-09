
rule VirTool_Win32_Obfuscator_ZAM_bit{
	meta:
		description = "VirTool:Win32/Obfuscator.ZAM!bit,SIGNATURE_TYPE_PEHSTR_EXT,64 00 03 00 04 00 00 "
		
	strings :
		$a_03_0 = {03 c8 89 4d ?? eb d6 8b 15 ?? ?? ?? 00 03 55 ?? 8a 45 ?? 88 02 83 7d ?? 00 74 0e 8b 0d ?? ?? ?? 00 03 4d ?? 8a 55 ?? 88 11 eb 81 } //2
		$a_03_1 = {03 45 98 8a 4d cc 88 08 83 7d d8 00 74 0e 8b 15 ?? ?? ?? 00 03 55 98 8a 45 cc 88 02 e9 ?? ?? ff ff } //2
		$a_03_2 = {74 25 6a 00 68 ?? ?? ?? 00 ff 15 ?? ?? ?? 00 85 c0 74 0a } //1
		$a_01_3 = {2f 00 2f 00 3a 00 3a 00 2b 00 2b 00 2a 00 2a 00 73 00 33 00 2f 00 2f 00 2f 00 66 00 } //1 //::++**s3///f
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2+(#a_03_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}