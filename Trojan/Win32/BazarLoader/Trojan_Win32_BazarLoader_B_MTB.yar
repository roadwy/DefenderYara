
rule Trojan_Win32_BazarLoader_B_MTB{
	meta:
		description = "Trojan:Win32/BazarLoader.B!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {8a 11 88 55 ?? 0f b6 45 ?? c1 f8 ?? 0f b6 4d ?? c1 e1 ?? 0b c1 0f b6 55 ?? 33 c2 8b 4d } //2
		$a_03_1 = {8b 45 dc 83 c0 ?? 99 b9 ?? ?? ?? ?? f7 f9 89 55 } //2
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2) >=4
 
}