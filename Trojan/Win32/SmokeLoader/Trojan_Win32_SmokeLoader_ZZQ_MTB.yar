
rule Trojan_Win32_SmokeLoader_ZZQ_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.ZZQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b d0 c1 ea 05 03 54 24 2c 8b c8 c1 e1 04 89 54 24 18 03 cd 8d 14 06 33 ca 89 4c 24 10 89 3d ?? ?? ?? ?? 8b 44 24 18 01 05 ?? ?? ?? ?? a1 ?? ?? ?? ?? 89 44 24 34 89 7c 24 18 8b 44 24 34 01 44 24 18 8b 44 24 10 33 44 24 18 89 44 24 18 8b 4c 24 18 } //1
		$a_03_1 = {33 c7 89 44 24 10 8b 44 24 18 31 44 24 10 8b 44 24 10 29 44 24 1c 81 c6 ?? ?? ?? ?? ff 4c 24 24 0f 85 d5 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}