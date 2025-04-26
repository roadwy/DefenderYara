
rule TrojanDropper_Win32_Cutwail_Y{
	meta:
		description = "TrojanDropper:Win32/Cutwail.Y,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 05 00 00 "
		
	strings :
		$a_02_0 = {64 8b 0d 18 00 00 00 8b 49 30 8b 1d ?? ?? 40 00 89 59 08 c3 } //1
		$a_02_1 = {25 00 00 ff ff 05 00 ?? 00 } //1
		$a_02_2 = {30 1f 80 c3 ?? e8 1a 00 00 00 30 0f 80 c1 ?? e8 10 00 00 00 30 17 80 c2 ?? e8 06 00 00 00 eb e0 } //1
		$a_02_3 = {8b f0 c1 e6 03 ff 15 ?? ?? ?? ?? 8b e5 ff 15 ?? ?? ?? ?? 83 c0 ?? 03 c6 } //1
		$a_02_4 = {33 f6 0b f0 c1 e6 03 8d 1d ?? ?? ?? ?? ff 93 ?? ?? ?? ?? 8b e5 8d 15 ?? ?? ?? ?? ff 92 ?? ?? ?? ?? b9 ?? ?? ?? ?? 03 c1 03 c6 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1+(#a_02_2  & 1)*1+(#a_02_3  & 1)*1+(#a_02_4  & 1)*1) >=2
 
}