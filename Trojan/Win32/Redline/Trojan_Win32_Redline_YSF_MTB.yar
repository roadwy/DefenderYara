
rule Trojan_Win32_Redline_YSF_MTB{
	meta:
		description = "Trojan:Win32/Redline.YSF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b d0 c1 ea 05 03 54 24 20 03 cd 33 d1 03 c6 33 d0 2b fa 8b cf c1 e1 04 81 3d ?? ?? ?? ?? 8c 07 00 00 c7 05 c8 48 2d 02 00 00 00 00 89 4c 24 10 75 } //1
		$a_03_1 = {33 f3 31 74 24 10 8b 44 24 10 29 44 24 14 81 3d ?? ?? ?? ?? 93 00 00 00 75 ?? 68 68 40 40 00 8d 44 24 74 50 ff 15 b8 10 40 00 8d 44 24 18 e8 ?? ?? ?? ?? ff 4c 24 1c 0f 85 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}