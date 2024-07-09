
rule TrojanDropper_Win32_AceLog_B_dha{
	meta:
		description = "TrojanDropper:Win32/AceLog.B!dha,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {b8 4d 5a 00 00 83 c4 04 66 39 07 74 ?? 68 c1 00 00 00 ff 15 [0-30] 8b 47 3c 81 3c 07 50 45 00 00 75 ?? 8b 47 1c 8b b5 ?? ?? ?? ?? 8b 4f 20 2b f0 85 c9 74 04 8b f1 2b f0 53 56 6a 08 ff 15 ?? ?? ?? ?? 50 ff 15 ?? ?? ?? ?? 8b 4f 1c } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule TrojanDropper_Win32_AceLog_B_dha_2{
	meta:
		description = "TrojanDropper:Win32/AceLog.B!dha,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 03 00 00 "
		
	strings :
		$a_03_0 = {0f b7 8c 05 ?? ?? ff ff 66 31 8c 05 ?? ?? ff ff 0f b7 8c 05 ?? ?? ff ff 66 31 8c 05 ?? ?? ff ff 0f b7 8c 05 ?? ?? ff ff 66 31 8c 05 ?? ?? ff ff 0f b7 8c 05 ?? ?? ff ff 66 31 8c 05 ?? ?? ff ff 83 c0 08 3d 00 01 00 00 72 b6 } //1
		$a_03_1 = {0f b7 84 0d ?? ?? ff ff 66 31 84 0d ?? ?? ff ff 0f b7 84 0d ?? ?? ff ff 66 31 84 0d ?? ?? ff ff 0f b7 84 0d ?? ?? ff ff 66 31 84 0d ?? ?? ff ff 0f b7 84 0d ?? ?? ff ff 66 31 84 0d ?? ?? ff ff 83 c1 08 81 f9 00 01 00 00 72 b5 } //1
		$a_03_2 = {63 6d 64 20 2f ?? 20 44 45 4c 20 00 20 22 00 00 } //10
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*10) >=11
 
}