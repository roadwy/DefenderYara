
rule Trojan_Win32_ICLoader_CCJT_MTB{
	meta:
		description = "Trojan:Win32/ICLoader.CCJT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {0b c8 33 d0 89 4c 24 00 33 c9 89 4c 24 04 [0-06] df 6c 24 00 } //2
		$a_03_1 = {89 0e ff 15 ?? ?? 89 00 a0 ?? ?? 8a 00 8a 0d ?? ?? 8a 00 8b 15 ?? ?? 8a 00 22 c8 a1 ?? ?? 8a 00 88 0d ?? ?? 8a 00 8b c8 8b 3d ?? ?? 89 00 c1 e9 02 2b d1 33 c9 } //1
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*1) >=3
 
}