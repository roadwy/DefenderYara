
rule VirTool_Win64_Thedstikspoz_A_MTB{
	meta:
		description = "VirTool:Win64/Thedstikspoz.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {66 c7 45 c8 49 ba 66 c7 45 d2 41 ff 48 8d ?? ?? ?? ?? ?? 48 89 45 ca 89 7d c4 45 32 ff 48 8b ?? ?? ?? ?? ?? 0f 10 00 0f ?? ?? ?? ?? ?? ?? 4c 8d ?? ?? ba 0d 00 00 00 44 8d ?? ?? 48 8b c8 } //1
		$a_03_1 = {41 b9 04 00 00 00 41 b8 00 10 00 00 49 8b d4 33 c9 ff 15 ?? ?? ?? ?? 4c 8b f8 48 85 c0 } //1
		$a_03_2 = {48 89 5d e8 48 89 7c 24 28 89 7c 24 20 4d 8b cf 4c 8d ?? ?? ?? ?? ?? 33 d2 33 c9 ff 15 ?? ?? ?? ?? 48 8b f8 48 89 45 d0 4c 8b f0 48 85 c0 } //1
		$a_03_3 = {48 89 7c 24 30 89 7c 24 28 c7 44 24 20 03 00 00 00 45 33 c9 ba 00 00 00 80 45 8d ?? ?? 48 8b 4b 08 ff 15 ?? ?? ?? ?? 4c 8b f0 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1) >=4
 
}