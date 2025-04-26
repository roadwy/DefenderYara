
rule VirTool_Win32_Obfuscator_VO{
	meta:
		description = "VirTool:Win32/Obfuscator.VO,SIGNATURE_TYPE_PEHSTR_EXT,64 00 03 00 04 00 00 "
		
	strings :
		$a_03_0 = {ff ff 00 8d 85 ?? ?? ff ff 50 51 e8 ?? ?? 00 00 ff d0 8b 85 ?? ?? ff ff 3d ?? ?? 00 00 75 02 c9 c3 } //1
		$a_01_1 = {8b 45 f4 eb 02 eb 10 48 c1 e8 0f c1 e0 0f 0f b7 08 } //2
		$a_01_2 = {c6 85 5c fd ff ff 5a } //1
		$a_03_3 = {8b 85 dc fd ff ff 83 e0 f0 3d ?? 92 00 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1) >=3
 
}