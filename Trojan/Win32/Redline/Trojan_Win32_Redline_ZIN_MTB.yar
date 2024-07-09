
rule Trojan_Win32_Redline_ZIN_MTB{
	meta:
		description = "Trojan:Win32/Redline.ZIN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b c1 c1 e8 05 03 44 24 2c 03 d5 33 c2 03 cb 33 c1 2b f0 8b d6 c1 e2 04 89 44 24 18 c7 05 ?? ?? ?? ?? 00 00 00 00 89 54 24 10 8b 44 24 } //1
		$a_03_1 = {8b c6 c1 e8 05 c7 05 ?? ?? ?? ?? 19 36 6b ff c7 05 ?? ?? ?? ?? ff ff ff ff 89 44 24 18 8b 44 24 28 01 44 24 18 81 3d ?? ?? ?? ?? 79 09 00 00 75 ?? 6a 00 ff 15 ?? ?? ?? ?? 8b 4c 24 18 33 cf 31 4c 24 10 8b 44 24 10 29 44 24 14 8b 3d ?? ?? ?? ?? 81 ff 93 00 00 00 74 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}